//! Safe-Rust Linux retained-capability filesystem boundary.
//!
//! Every authoritative descendant operation is relative to a retained
//! `cap_std::fs::Dir` and uses the exact `rustix` operations frozen by
//! NAR-DC-P1-005. This module contains no ambient production path operation,
//! no `openat` fallback, and no application `unsafe`.

use cap_std::fs::Dir;
use nix::unistd::{fpathconf, PathconfVar};
use rustix::{
    fd::OwnedFd,
    fs::{
        fchmod, flock, fstat, fsync, mkdirat, openat2, renameat, renameat_with, statat, unlinkat,
        AtFlags, FileType, FlockOperation, Mode, OFlags, RawDir, RenameFlags, ResolveFlags, Stat,
    },
    io::Errno,
    process::geteuid,
};
use std::{
    error::Error,
    fmt,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::MaybeUninit,
    os::fd::AsFd,
    sync::Arc,
};

mod backup;
mod inventory;
mod restore;
mod session_store;
#[cfg(all(test, feature = "evidence-only"))]
mod signer_e2e;

#[cfg(feature = "evidence-only")]
pub use backup::{BackupPolicyLimitsV1, CompletedBackupV1};
pub use inventory::{ContractsNonceVaultV1, InventoryError, RetainedRestoreTargetV1};
pub use session_store::{
    verify_funding_artifacts_v1, verify_operational_funding_gate_evidence_v1,
    verify_operational_m8_funding_gate_evidence_v1, AcceptedContractsSigningSessionV1,
    AuthenticatedContractsRefundV1, AuthenticatedOperationalBpContinuationV1,
    AuthenticatedOperationalBpFinalProofV1, AuthenticatedPostAnchorClaimPreSignatureV1,
    ClaimSigningAuthorizationV1, ConsumedClaimSigningAuthorizationV1,
    ContractsReservationLookupCustodyV1, ContractsSessionStoreV1,
    ContractsSigningSessionAuthorityV1, DomTransactionValidationContextV1,
    DurableContractsReservationLookupV1, DurableTransportOutcomeV1, DurableTransportReceiptV1,
    ExactDomFundingBroadcasterV1, ExactDomRefundBroadcasterV1, FundingAuthorizationV1,
    FundingBroadcastV1, FundingRetransmissionV1, OperationalBpContinuationStageV1,
    OperationalFundingGateVerificationRequestV1, OperationalM8FundingGateVerificationRequestV1,
    PreparedOperationalM8FundingGateV1, PreparedOperationalM8ReadyToFundVoteV1, RefundBroadcastV1,
    SessionStoreError, SessionTransportIdentityReferenceV1, SessionTransportParticipantV1,
    TerminalCollaborativeSessionEvidenceV1, VerifiedFundingArtifactsV1,
    VerifiedOperationalFundingGateEvidenceV1, VerifiedOperationalM8FundingGateEvidenceV1,
};

const REQUIRED_COMPONENT_LIMIT: i64 = 229;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const DIRECTORY_SCAN_BUFFER_LEN: usize = 8_192;

const RESOLVE_FLAGS: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// Redacted failure from the retained Linux filesystem boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinuxCapabilityError {
    /// A path component is not a member of the signed component registry.
    InvalidComponent,
    /// A required kernel or filesystem primitive is unavailable.
    UnsupportedFilesystem,
    /// A create-no-clobber or rename-no-replace destination already exists.
    AlreadyExists,
    /// A required exact object does not exist.
    NotFound,
    /// Another retained store authority owns the exclusive lock.
    StoreBusy,
    /// An opened object has the wrong type, owner, mode, or link count.
    InvalidObject,
    /// A retained object was replaced or no longer matches its authenticated identity.
    IdentityMismatch,
    /// An exact read was truncated, extended, or differed from expected bytes.
    ExactBytesMismatch,
    /// A bounded scan could not decode an operating-system directory entry.
    InvalidDirectoryEntry,
    /// A filesystem operation failed; the operation name and OS code reveal no path.
    OperationFailed {
        /// Static operation identifier.
        operation: &'static str,
        /// Operating-system error code, when one was available.
        os_code: Option<i32>,
    },
}

impl fmt::Display for LinuxCapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidComponent => formatter.write_str("invalid retained-store component"),
            Self::UnsupportedFilesystem => {
                formatter.write_str("required retained filesystem primitive is unavailable")
            }
            Self::AlreadyExists => formatter.write_str("retained-store object already exists"),
            Self::NotFound => formatter.write_str("retained-store object was not found"),
            Self::StoreBusy => formatter.write_str("retained store is busy"),
            Self::InvalidObject => formatter.write_str("invalid retained-store object"),
            Self::IdentityMismatch => formatter.write_str("retained-store object identity changed"),
            Self::ExactBytesMismatch => {
                formatter.write_str("retained-store exact-byte verification failed")
            }
            Self::InvalidDirectoryEntry => {
                formatter.write_str("invalid retained-store directory entry")
            }
            Self::OperationFailed { operation, os_code } => {
                write!(
                    formatter,
                    "retained filesystem operation {operation} failed"
                )?;
                if let Some(code) = os_code {
                    write!(formatter, " with OS error {code}")?;
                }
                Ok(())
            }
        }
    }
}

impl Error for LinuxCapabilityError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedNodeType {
    Directory,
    RegularFile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedComponent {
    value: String,
    expected_type: ExpectedNodeType,
}

impl ValidatedComponent {
    fn operator_selected_root(value: &str) -> Result<Self, LinuxCapabilityError> {
        validate_single_component(value)?;
        if value.len() > REQUIRED_COMPONENT_LIMIT as usize
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        Ok(Self {
            value: value.to_owned(),
            expected_type: ExpectedNodeType::Directory,
        })
    }

    fn registered(value: &str) -> Result<Self, LinuxCapabilityError> {
        validate_single_component(value)?;
        let expected_type =
            classify_registered_component(value).ok_or(LinuxCapabilityError::InvalidComponent)?;
        Ok(Self {
            value: value.to_owned(),
            expected_type,
        })
    }

    fn as_str(&self) -> &str {
        &self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NodeIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    link_count: u64,
    owner: u32,
    node_type: ExpectedNodeType,
}

impl NodeIdentity {
    fn from_stat(
        stat: &Stat,
        expected_type: ExpectedNodeType,
    ) -> Result<Self, LinuxCapabilityError> {
        let actual_type = FileType::from_raw_mode(stat.st_mode);
        let expected_mode = match expected_type {
            ExpectedNodeType::Directory => DIRECTORY_MODE,
            ExpectedNodeType::RegularFile => FILE_MODE,
        };
        let type_matches = match expected_type {
            ExpectedNodeType::Directory => actual_type.is_dir(),
            ExpectedNodeType::RegularFile => actual_type.is_file(),
        };
        if !type_matches
            || stat.st_uid != geteuid().as_raw()
            || Mode::from_raw_mode(stat.st_mode).bits() != expected_mode
            || stat.st_nlink == 0
            || (expected_type == ExpectedNodeType::RegularFile && stat.st_nlink != 1)
        {
            return Err(LinuxCapabilityError::InvalidObject);
        }
        Ok(Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            link_count: stat.st_nlink,
            owner: stat.st_uid,
            node_type: expected_type,
        })
    }

    fn from_fd<Fd: AsFd>(
        fd: Fd,
        expected_type: ExpectedNodeType,
    ) -> Result<Self, LinuxCapabilityError> {
        let stat = fstat(fd).map_err(|error| map_errno("fstat", error))?;
        Self::from_stat(&stat, expected_type)
    }

    fn require_same(&self, other: &Self) -> Result<(), LinuxCapabilityError> {
        let stable_identity_matches = self.device == other.device
            && self.inode == other.inode
            && self.mode == other.mode
            && self.owner == other.owner
            && self.node_type == other.node_type;
        let link_policy_matches = match self.node_type {
            ExpectedNodeType::RegularFile => self.link_count == 1 && other.link_count == 1,
            ExpectedNodeType::Directory => self.link_count != 0 && other.link_count != 0,
        };
        if stable_identity_matches && link_policy_matches {
            Ok(())
        } else {
            Err(LinuxCapabilityError::IdentityMismatch)
        }
    }
}

struct ReopenAuthority {
    parent: Arc<Dir>,
    component: ValidatedComponent,
}

struct RetainedDirectory {
    descriptor: Arc<Dir>,
    identity: NodeIdentity,
    reopen: ReopenAuthority,
}

impl RetainedDirectory {
    /// Retains an independent alias of the same already-validated directory
    /// capability without reopening it through an ambient path.
    fn retained_alias(&self) -> Result<Self, LinuxCapabilityError> {
        self.revalidate()?;
        Ok(Self {
            descriptor: Arc::clone(&self.descriptor),
            identity: self.identity,
            reopen: ReopenAuthority {
                parent: Arc::clone(&self.reopen.parent),
                component: self.reopen.component.clone(),
            },
        })
    }

    fn create_under(
        parent: Arc<Dir>,
        component: ValidatedComponent,
    ) -> Result<Self, LinuxCapabilityError> {
        if component.expected_type != ExpectedNodeType::Directory {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        require_name_max(parent.as_ref())?;
        require_synchronizable_directory(parent.as_ref())?;
        #[cfg(test)]
        backup::test_crash_hook("before-directory-create");
        mkdirat(
            parent.as_fd(),
            component.as_str(),
            Mode::from_raw_mode(DIRECTORY_MODE),
        )
        .map_err(|error| map_errno("mkdirat", error))?;
        #[cfg(test)]
        backup::test_crash_hook("after-directory-create-before-parent-sync");
        let descriptor = open_directory_fd(parent.as_ref(), &component)?;
        fchmod(descriptor.as_fd(), Mode::from_raw_mode(DIRECTORY_MODE))
            .map_err(|error| map_errno("fchmod-directory", error))?;
        let identity = NodeIdentity::from_fd(descriptor.as_fd(), ExpectedNodeType::Directory)?;
        fsync(parent.as_fd()).map_err(|error| map_errno("fsync-parent-directory", error))?;
        #[cfg(test)]
        backup::test_crash_hook("after-directory-parent-sync");
        let descriptor = Arc::new(Dir::from_std_file(File::from(descriptor)));
        Ok(Self {
            descriptor,
            identity,
            reopen: ReopenAuthority { parent, component },
        })
    }

    fn open_under(
        parent: Arc<Dir>,
        component: ValidatedComponent,
    ) -> Result<Self, LinuxCapabilityError> {
        if component.expected_type != ExpectedNodeType::Directory {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        require_name_max(parent.as_ref())?;
        require_synchronizable_directory(parent.as_ref())?;
        let descriptor = open_directory_fd(parent.as_ref(), &component)?;
        let identity = NodeIdentity::from_fd(descriptor.as_fd(), ExpectedNodeType::Directory)?;
        let descriptor = Arc::new(Dir::from_std_file(File::from(descriptor)));
        Ok(Self {
            descriptor,
            identity,
            reopen: ReopenAuthority { parent, component },
        })
    }

    fn create_child_directory(
        &self,
        component: ValidatedComponent,
    ) -> Result<Self, LinuxCapabilityError> {
        Self::create_under(Arc::clone(&self.descriptor), component)
    }

    fn open_child_directory(
        &self,
        component: ValidatedComponent,
    ) -> Result<Self, LinuxCapabilityError> {
        Self::open_under(Arc::clone(&self.descriptor), component)
    }

    fn sync(&self) -> Result<(), LinuxCapabilityError> {
        self.revalidate()?;
        fsync(self.descriptor.as_fd()).map_err(|error| map_errno("fsync-directory", error))
    }

    fn create_immutable_file(
        &self,
        component: &ValidatedComponent,
        exact_bytes: &[u8],
    ) -> Result<RetainedFile, LinuxCapabilityError> {
        if component.expected_type != ExpectedNodeType::RegularFile {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        require_name_max(self.descriptor.as_ref())?;
        let descriptor = openat2(
            self.descriptor.as_fd(),
            component.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(FILE_MODE),
            RESOLVE_FLAGS,
        )
        .map_err(|error| map_errno("openat2-create-file", error))?;
        #[cfg(test)]
        backup::test_crash_hook("after-file-create-before-write");
        fchmod(descriptor.as_fd(), Mode::from_raw_mode(FILE_MODE))
            .map_err(|error| map_errno("fchmod-file", error))?;
        let mut file = File::from(descriptor);
        #[cfg(test)]
        if backup::test_crash_cut_matches("during-proper-prefix-write") && exact_bytes.len() > 1 {
            let prefix_length = exact_bytes.len() / 2;
            file.write_all(&exact_bytes[..prefix_length])
                .map_err(|error| map_io("write-proper-prefix", error))?;
            backup::test_crash_hook("during-proper-prefix-write");
        }
        file.write_all(exact_bytes)
            .map_err(|error| map_io("write-all", error))?;
        #[cfg(test)]
        backup::test_crash_hook("after-full-write-before-file-sync");
        fsync(file.as_fd()).map_err(|error| map_errno("fsync-file", error))?;
        #[cfg(test)]
        backup::test_crash_hook("after-file-sync-before-parent-sync");
        let _created_identity = NodeIdentity::from_fd(file.as_fd(), ExpectedNodeType::RegularFile)?;
        fsync(self.descriptor.as_fd())
            .map_err(|error| map_errno("fsync-parent-directory", error))?;
        #[cfg(test)]
        backup::test_crash_hook("after-file-parent-sync-before-reopen");
        drop(file);
        let mut reopened = self.open_file(component, false)?;
        reopened.require_exact_bytes(exact_bytes)?;
        reopened.revalidate()?;
        #[cfg(test)]
        backup::test_crash_hook("after-file-reopen");
        Ok(reopened)
    }

    fn open_file(
        &self,
        component: &ValidatedComponent,
        writable: bool,
    ) -> Result<RetainedFile, LinuxCapabilityError> {
        if component.expected_type != ExpectedNodeType::RegularFile {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        let access = if writable {
            OFlags::RDWR
        } else {
            OFlags::RDONLY
        };
        let descriptor = openat2(
            self.descriptor.as_fd(),
            component.as_str(),
            access | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            RESOLVE_FLAGS,
        )
        .map_err(|error| map_errno("openat2-file", error))?;
        let file = File::from(descriptor);
        let identity = NodeIdentity::from_fd(file.as_fd(), ExpectedNodeType::RegularFile)?;
        Ok(RetainedFile { file, identity })
    }

    fn rename_no_replace(
        &self,
        source: &ValidatedComponent,
        destination: &ValidatedComponent,
        retained_source: &RetainedFile,
    ) -> Result<(), LinuxCapabilityError> {
        if source.expected_type != ExpectedNodeType::RegularFile
            || destination.expected_type != ExpectedNodeType::RegularFile
        {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        self.require_named_file_identity(source, retained_source)?;
        renameat_with(
            self.descriptor.as_fd(),
            source.as_str(),
            self.descriptor.as_fd(),
            destination.as_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| map_errno("renameat2-no-replace", error))?;
        fsync(self.descriptor.as_fd())
            .map_err(|error| map_errno("fsync-parent-directory", error))?;
        let destination_stat = statat(
            self.descriptor.as_fd(),
            destination.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| map_errno("statat-renamed-file", error))?;
        let destination_identity =
            NodeIdentity::from_stat(&destination_stat, ExpectedNodeType::RegularFile)?;
        retained_source.identity.require_same(&destination_identity)
    }

    fn rename_generation_no_replace(
        &self,
        staging: &ValidatedComponent,
        destination: &ValidatedComponent,
        retained_staging: &RetainedDirectory,
    ) -> Result<RetainedDirectory, LinuxCapabilityError> {
        if staging.expected_type != ExpectedNodeType::Directory
            || destination.expected_type != ExpectedNodeType::Directory
            || !generation_component(destination.as_str(), false)
            || staging.as_str() != format!(".{}.staging", destination.as_str())
        {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        retained_staging.revalidate()?;
        let named_stat = statat(
            self.descriptor.as_fd(),
            staging.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| map_errno("statat-staging-generation", error))?;
        let named_identity = NodeIdentity::from_stat(&named_stat, ExpectedNodeType::Directory)?;
        retained_staging.identity.require_same(&named_identity)?;
        renameat_with(
            self.descriptor.as_fd(),
            staging.as_str(),
            self.descriptor.as_fd(),
            destination.as_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| map_errno("renameat2-generation-no-replace", error))?;
        fsync(self.descriptor.as_fd())
            .map_err(|error| map_errno("fsync-parent-directory", error))?;
        let destination_stat = statat(
            self.descriptor.as_fd(),
            destination.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| map_errno("statat-renamed-generation", error))?;
        let destination_identity =
            NodeIdentity::from_stat(&destination_stat, ExpectedNodeType::Directory)?;
        retained_staging
            .identity
            .require_same(&destination_identity)?;
        self.open_child_directory(destination.clone())
    }

    /// Publishes one fully verified restore staging tree under the unique
    /// `restore-pending` name. Both handles must prove that the staging tree is
    /// an immediate child of this retained root; no ambient path participates.
    fn publish_restore_staging_no_replace(
        &self,
        staging: &ValidatedComponent,
        retained_staging: &RetainedDirectory,
    ) -> Result<RetainedDirectory, LinuxCapabilityError> {
        let pending = ValidatedComponent::registered("restore-pending")?;
        if staging.expected_type != ExpectedNodeType::Directory
            || !exact_wrapped_hex(staging.as_str(), ".restore-", 32, ".staging")
            || &retained_staging.reopen.component != staging
            || !Arc::ptr_eq(&retained_staging.reopen.parent, &self.descriptor)
        {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        retained_staging.revalidate()?;
        let source_stat = statat(
            self.descriptor.as_fd(),
            staging.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| map_errno("statat-restore-staging", error))?;
        let source_identity = NodeIdentity::from_stat(&source_stat, ExpectedNodeType::Directory)?;
        retained_staging.identity.require_same(&source_identity)?;
        renameat_with(
            self.descriptor.as_fd(),
            staging.as_str(),
            self.descriptor.as_fd(),
            pending.as_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| map_errno("renameat2-restore-pending", error))?;
        #[cfg(test)]
        restore::test_restore_crash_hook("step9-after-rename-before-root-sync");
        fsync(self.descriptor.as_fd()).map_err(|error| map_errno("fsync-restore-root", error))?;
        let published = self.open_child_directory(pending)?;
        retained_staging
            .identity
            .require_same(&published.identity)?;
        Ok(published)
    }

    /// Moves the exact verified successor-generation directory from the
    /// retained pending tree into its immutable root generation name.
    fn activate_restore_generation_no_replace(
        &self,
        pending: &RetainedDirectory,
        successor: &RetainedDirectory,
        destination: &ValidatedComponent,
    ) -> Result<RetainedDirectory, LinuxCapabilityError> {
        if pending.reopen.component.as_str() != "restore-pending"
            || !Arc::ptr_eq(&pending.reopen.parent, &self.descriptor)
            || successor.reopen.component.as_str() != "successor-generation"
            || !Arc::ptr_eq(&successor.reopen.parent, &pending.descriptor)
            || destination.expected_type != ExpectedNodeType::Directory
            || !generation_component(destination.as_str(), false)
        {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        pending.revalidate()?;
        successor.revalidate()?;
        let source_stat = statat(
            pending.descriptor.as_fd(),
            successor.reopen.component.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| map_errno("statat-restore-successor", error))?;
        let source_identity = NodeIdentity::from_stat(&source_stat, ExpectedNodeType::Directory)?;
        successor.identity.require_same(&source_identity)?;
        renameat_with(
            pending.descriptor.as_fd(),
            successor.reopen.component.as_str(),
            self.descriptor.as_fd(),
            destination.as_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| map_errno("renameat2-restore-successor", error))?;
        #[cfg(test)]
        restore::test_restore_crash_hook("step10-after-rename-before-root-sync");
        fsync(pending.descriptor.as_fd())
            .map_err(|error| map_errno("fsync-restore-pending", error))?;
        fsync(self.descriptor.as_fd()).map_err(|error| map_errno("fsync-restore-root", error))?;
        let activated = self.open_child_directory(destination.clone())?;
        successor.identity.require_same(&activated.identity)?;
        Ok(activated)
    }

    /// Replaces the live active pointer only with the exact retained activation
    /// file nested in the unique pending restore transaction.
    fn activate_restore_pointer(
        &self,
        pending: &RetainedDirectory,
        activation: &RetainedDirectory,
        retained_active: &RetainedFile,
    ) -> Result<(), LinuxCapabilityError> {
        let source = ValidatedComponent::registered("active-generation.bin")?;
        let destination = ValidatedComponent::registered("active-vault-generation")?;
        if pending.reopen.component.as_str() != "restore-pending"
            || !Arc::ptr_eq(&pending.reopen.parent, &self.descriptor)
            || activation.reopen.component.as_str() != "activation"
            || !Arc::ptr_eq(&activation.reopen.parent, &pending.descriptor)
        {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        pending.revalidate()?;
        activation.revalidate()?;
        activation.require_named_file_identity(&source, retained_active)?;
        renameat(
            activation.descriptor.as_fd(),
            source.as_str(),
            self.descriptor.as_fd(),
            destination.as_str(),
        )
        .map_err(|error| map_errno("renameat-restore-active-pointer", error))?;
        #[cfg(test)]
        restore::test_restore_crash_hook("step11-after-rename-before-root-sync");
        fsync(activation.descriptor.as_fd())
            .map_err(|error| map_errno("fsync-restore-activation", error))?;
        fsync(self.descriptor.as_fd()).map_err(|error| map_errno("fsync-restore-root", error))?;
        let destination_stat = statat(
            self.descriptor.as_fd(),
            destination.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| map_errno("statat-restore-active-pointer", error))?;
        let destination_identity =
            NodeIdentity::from_stat(&destination_stat, ExpectedNodeType::RegularFile)?;
        retained_active.identity.require_same(&destination_identity)
    }

    /// Retains the complete restore transaction by moving only the exact
    /// `restore-pending` directory to its canonical immutable completed name.
    fn retain_completed_restore_no_replace(
        &self,
        pending: &RetainedDirectory,
        completed: &ValidatedComponent,
    ) -> Result<RetainedDirectory, LinuxCapabilityError> {
        if pending.reopen.component.as_str() != "restore-pending"
            || !Arc::ptr_eq(&pending.reopen.parent, &self.descriptor)
            || completed.expected_type != ExpectedNodeType::Directory
            || !exact_wrapped_hex(completed.as_str(), "restore-complete-", 32, "")
        {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        pending.revalidate()?;
        let source_stat = statat(
            self.descriptor.as_fd(),
            pending.reopen.component.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| map_errno("statat-restore-pending", error))?;
        let source_identity = NodeIdentity::from_stat(&source_stat, ExpectedNodeType::Directory)?;
        pending.identity.require_same(&source_identity)?;
        renameat_with(
            self.descriptor.as_fd(),
            pending.reopen.component.as_str(),
            self.descriptor.as_fd(),
            completed.as_str(),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| map_errno("renameat2-restore-complete", error))?;
        #[cfg(test)]
        restore::test_restore_crash_hook("step13-after-rename-before-root-sync");
        fsync(self.descriptor.as_fd()).map_err(|error| map_errno("fsync-restore-root", error))?;
        let retained = self.open_child_directory(completed.clone())?;
        pending.identity.require_same(&retained.identity)?;
        Ok(retained)
    }

    fn replace_active_pointer(
        &self,
        staging: &ValidatedComponent,
        destination: &ValidatedComponent,
        retained_staging: &RetainedFile,
    ) -> Result<(), LinuxCapabilityError> {
        if staging.as_str() != ".active-vault-generation.staging"
            || destination.as_str() != "active-vault-generation"
            || staging.expected_type != ExpectedNodeType::RegularFile
            || destination.expected_type != ExpectedNodeType::RegularFile
        {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        self.require_named_file_identity(staging, retained_staging)?;
        renameat(
            self.descriptor.as_fd(),
            staging.as_str(),
            self.descriptor.as_fd(),
            destination.as_str(),
        )
        .map_err(|error| map_errno("renameat-active-pointer", error))?;
        fsync(self.descriptor.as_fd())
            .map_err(|error| map_errno("fsync-parent-directory", error))?;
        let destination_stat = statat(
            self.descriptor.as_fd(),
            destination.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| map_errno("statat-active-pointer", error))?;
        let destination_identity =
            NodeIdentity::from_stat(&destination_stat, ExpectedNodeType::RegularFile)?;
        retained_staging
            .identity
            .require_same(&destination_identity)
    }

    fn unlink_verified_file(
        &self,
        component: &ValidatedComponent,
        retained: &RetainedFile,
    ) -> Result<(), LinuxCapabilityError> {
        if component.expected_type != ExpectedNodeType::RegularFile {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        self.require_named_file_identity(component, retained)?;
        unlinkat(
            self.descriptor.as_fd(),
            component.as_str(),
            AtFlags::empty(),
        )
        .map_err(|error| map_errno("unlinkat", error))?;
        fsync(self.descriptor.as_fd())
            .map_err(|error| map_errno("fsync-parent-directory", error))?;
        match statat(
            self.descriptor.as_fd(),
            component.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(Errno::NOENT) => Ok(()),
            Ok(_) => Err(LinuxCapabilityError::IdentityMismatch),
            Err(error) => Err(map_errno("statat-after-unlink", error)),
        }
    }

    fn require_named_file_identity(
        &self,
        component: &ValidatedComponent,
        retained: &RetainedFile,
    ) -> Result<(), LinuxCapabilityError> {
        if component.expected_type != ExpectedNodeType::RegularFile {
            return Err(LinuxCapabilityError::InvalidComponent);
        }
        retained.revalidate()?;
        let named_stat = statat(
            self.descriptor.as_fd(),
            component.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| map_errno("statat-named-file", error))?;
        let named_identity = NodeIdentity::from_stat(&named_stat, ExpectedNodeType::RegularFile)?;
        retained.identity.require_same(&named_identity)
    }

    fn acquire_lock(
        &self,
        component: &ValidatedComponent,
    ) -> Result<RetainedExclusiveLock, LinuxCapabilityError> {
        let lock_file = self.open_file(component, true)?;
        flock(
            lock_file.file.as_fd(),
            FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|error| map_errno("flock-exclusive", error))?;
        self.revalidate()?;
        self.require_named_file_identity(component, &lock_file)?;
        Ok(RetainedExclusiveLock {
            parent: Arc::clone(&self.descriptor),
            component: component.clone(),
            lock_file,
        })
    }

    fn revalidate(&self) -> Result<(), LinuxCapabilityError> {
        let live = NodeIdentity::from_fd(self.descriptor.as_fd(), ExpectedNodeType::Directory)?;
        self.identity.require_same(&live)?;
        let named = statat(
            self.reopen.parent.as_fd(),
            self.reopen.component.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| map_errno("statat-directory", error))?;
        let named = NodeIdentity::from_stat(&named, ExpectedNodeType::Directory)?;
        self.identity.require_same(&named)
    }

    fn scan_independent<F>(&self, mut inspect: F) -> Result<(), LinuxCapabilityError>
    where
        F: FnMut(&str, NodeIdentity) -> Result<(), LinuxCapabilityError>,
    {
        self.revalidate()?;
        let descriptor = open_directory_fd(self.reopen.parent.as_ref(), &self.reopen.component)?;
        let live_identity = NodeIdentity::from_fd(descriptor.as_fd(), ExpectedNodeType::Directory)?;
        self.identity.require_same(&live_identity)?;
        let mut buffer = [MaybeUninit::<u8>::uninit(); DIRECTORY_SCAN_BUFFER_LEN];
        let mut entries = RawDir::new(&descriptor, &mut buffer);
        let mut scanned_entries = 0_u64;
        while let Some(entry) = entries.next() {
            let entry = entry.map_err(|error| map_errno("getdents", error))?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| LinuxCapabilityError::InvalidDirectoryEntry)?;
            if matches!(name, "." | "..") {
                continue;
            }
            scanned_entries = scanned_entries
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            let component = ValidatedComponent::registered(name)?;
            let stat = statat(
                descriptor.as_fd(),
                component.as_str(),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|error| map_errno("statat-scan-entry", error))?;
            let identity = NodeIdentity::from_stat(&stat, component.expected_type)?;
            inspect(name, identity)?;
        }
        Ok(())
    }

    fn scan_lexicographic<F>(&self, mut inspect: F) -> Result<(), LinuxCapabilityError>
    where
        F: FnMut(&str, NodeIdentity) -> Result<(), LinuxCapabilityError>,
    {
        let mut previous: Option<String> = None;
        loop {
            let mut next: Option<(String, NodeIdentity)> = None;
            self.scan_independent(|name, identity| {
                let is_after_previous = previous
                    .as_deref()
                    .map_or(true, |previous_name| name > previous_name);
                let is_before_next = next
                    .as_ref()
                    .map_or(true, |(next_name, _)| name < next_name.as_str());
                if is_after_previous && is_before_next {
                    next = Some((name.to_owned(), identity));
                }
                Ok(())
            })?;
            let Some((name, identity)) = next else {
                return Ok(());
            };
            inspect(&name, identity)?;
            previous = Some(name);
        }
    }

    fn read_bounded_file(
        &self,
        component: &ValidatedComponent,
        maximum_length: usize,
    ) -> Result<Vec<u8>, LinuxCapabilityError> {
        let mut retained = self.open_file(component, false)?;
        let bytes = retained.read_bounded(maximum_length)?;
        self.require_named_file_identity(component, &retained)?;
        Ok(bytes)
    }
}

struct RetainedFile {
    file: File,
    identity: NodeIdentity,
}

impl RetainedFile {
    fn revalidate(&self) -> Result<(), LinuxCapabilityError> {
        let live = NodeIdentity::from_fd(self.file.as_fd(), ExpectedNodeType::RegularFile)?;
        self.identity.require_same(&live)
    }

    fn require_exact_bytes(&mut self, expected: &[u8]) -> Result<(), LinuxCapabilityError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|error| map_io("seek-file", error))?;
        let expected_len = expected
            .len()
            .checked_add(1)
            .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
        let mut actual = Vec::with_capacity(expected_len);
        Read::by_ref(&mut self.file)
            .take(expected_len as u64)
            .read_to_end(&mut actual)
            .map_err(|error| map_io("read-exact-file", error))?;
        if actual == expected {
            Ok(())
        } else {
            Err(LinuxCapabilityError::ExactBytesMismatch)
        }
    }

    fn read_bounded(&mut self, maximum_length: usize) -> Result<Vec<u8>, LinuxCapabilityError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|error| map_io("seek-file", error))?;
        let read_limit = maximum_length
            .checked_add(1)
            .ok_or(LinuxCapabilityError::ExactBytesMismatch)?;
        let mut bytes = Vec::with_capacity(read_limit);
        Read::by_ref(&mut self.file)
            .take(read_limit as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| map_io("read-bounded-file", error))?;
        if bytes.len() > maximum_length {
            return Err(LinuxCapabilityError::ExactBytesMismatch);
        }
        self.revalidate()?;
        Ok(bytes)
    }
}

struct RetainedExclusiveLock {
    parent: Arc<Dir>,
    component: ValidatedComponent,
    lock_file: RetainedFile,
}

impl RetainedExclusiveLock {
    fn revalidate(&self) -> Result<(), LinuxCapabilityError> {
        self.lock_file.revalidate()?;
        let named_stat = statat(
            self.parent.as_fd(),
            self.component.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| map_errno("statat-retained-lock", error))?;
        let named_identity = NodeIdentity::from_stat(&named_stat, ExpectedNodeType::RegularFile)?;
        self.lock_file.identity.require_same(&named_identity)
    }
}

fn open_directory_fd(
    parent: &Dir,
    component: &ValidatedComponent,
) -> Result<OwnedFd, LinuxCapabilityError> {
    openat2(
        parent.as_fd(),
        component.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE_FLAGS,
    )
    .map_err(|error| map_errno("openat2-directory", error))
}

fn require_name_max(directory: &Dir) -> Result<(), LinuxCapabilityError> {
    let result = fpathconf(directory, PathconfVar::NAME_MAX)
        .map_err(|_| LinuxCapabilityError::UnsupportedFilesystem)?;
    match result {
        Some(limit) if limit >= REQUIRED_COMPONENT_LIMIT => Ok(()),
        _ => Err(LinuxCapabilityError::UnsupportedFilesystem),
    }
}

fn require_synchronizable_directory(directory: &Dir) -> Result<(), LinuxCapabilityError> {
    fsync(directory.as_fd()).map_err(|error| map_errno("fsync-directory-preflight", error))
}

fn validate_single_component(value: &str) -> Result<(), LinuxCapabilityError> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.len() > REQUIRED_COMPONENT_LIMIT as usize
        || value.bytes().any(|byte| matches!(byte, 0 | b'/' | b'\\'))
    {
        Err(LinuxCapabilityError::InvalidComponent)
    } else {
        Ok(())
    }
}

fn classify_registered_component(value: &str) -> Option<ExpectedNodeType> {
    let static_type = match value {
        "store-root-identity.bin"
        | "store-lock-identity.bin"
        | "active-vault-generation"
        | ".active-vault-generation.staging"
        | "restore-only-root.bin"
        | "generation-core.bin"
        | "master-key.envelope"
        | "backup-master-key.envelope"
        | "backup-manifest.object"
        | "backup-bundle.digest"
        | "restore-pending.index"
        | "restore-manifest.bin"
        | "active-generation.bin"
        | "session-store-root.bin"
        | "session-store-lock.bin"
        | "session-store-policy.bin" => Some(ExpectedNodeType::RegularFile),
        "restore-pending"
        | "journal"
        | "reservation-authorities"
        | "session-claims"
        | "budget-charges"
        | "attempts"
        | "exposures"
        | "nonce-secrets"
        | "collaborative-secrets"
        | "tombstones"
        | "records"
        | "source-backup"
        | "successor-generation"
        | "activation"
        | "session-records"
        | "session-artifacts"
        | "session-consumptions"
        | "session-rosters"
        | "session-messages"
        | "session-reservation-lookups" => Some(ExpectedNodeType::Directory),
        _ => None,
    };
    static_type.or_else(|| classify_dynamic_component(value))
}

fn classify_dynamic_component(value: &str) -> Option<ExpectedNodeType> {
    if exact_wrapped_hex(value, "restore-initialized-", 32, ".bin") {
        return Some(ExpectedNodeType::RegularFile);
    }
    if exact_wrapped_hex(value, ".restore-", 32, ".staging")
        || exact_wrapped_hex(value, "restore-complete-", 32, "")
        || generation_component(value, false)
        || generation_component(value, true)
        || backup_component(value, false)
        || backup_component(value, true)
        || is_lower_hex(value, 210)
        || is_decimal(value, 20)
    {
        return Some(ExpectedNodeType::Directory);
    }
    if exact_wrapped_hex(value, "", 64, ".authority")
        || exact_wrapped_hex(value, "", 64, ".claim")
        || decimal_hex_suffix(value, 20, 64, ".charge")
        || decimal_hex_suffix(value, 20, 2, ".attempt")
        || hex_hex_suffix(value, 2, 64, ".exposure")
        || exact_wrapped_hex(value, "", 210, ".secret")
        || exact_wrapped_hex(value, "", 210, ".tombstone")
        || exact_wrapped_hex(value, ".", 210, ".tombstone.staging")
        || collaborative_state_component(value, false)
        || collaborative_state_component(value, true)
        || decimal_hex_suffix(value, 20, 64, ".journal")
        || exact_wrapped_hex(value, "", 100, ".record")
        || session_revision_component(value, false)
        || session_revision_component(value, true)
        || exact_wrapped_hex(value, "", 64, ".funding-artifacts")
        || exact_wrapped_hex(value, ".", 64, ".funding-artifacts.staging")
        || exact_wrapped_hex(value, "", 64, ".operational-funding-gate")
        || exact_wrapped_hex(value, ".", 64, ".operational-funding-gate.staging")
        || exact_wrapped_hex(value, "", 64, ".operational-m8-funding-gate")
        || exact_wrapped_hex(value, ".", 64, ".operational-m8-funding-gate.staging")
        || exact_wrapped_hex(value, "", 64, ".operational-funding-issuance")
        || exact_wrapped_hex(value, ".", 64, ".operational-funding-issuance.staging")
        || exact_wrapped_hex(value, "", 64, ".operational-m8-funding-issuance")
        || exact_wrapped_hex(value, ".", 64, ".operational-m8-funding-issuance.staging")
        || exact_wrapped_hex(value, "", 64, ".operational-funding-commit")
        || exact_wrapped_hex(value, ".", 64, ".operational-funding-commit.staging")
        || exact_wrapped_hex(value, "", 64, ".operational-m8-funding-commit")
        || exact_wrapped_hex(value, ".", 64, ".operational-m8-funding-commit.staging")
        || exact_wrapped_hex(value, "", 64, ".post-anchor-claim-signing-issued")
        || exact_wrapped_hex(value, ".", 64, ".post-anchor-claim-signing-issued.staging")
        || exact_wrapped_hex(value, "", 64, ".post-anchor-claim-signing-consumed")
        || exact_wrapped_hex(
            value,
            ".",
            64,
            ".post-anchor-claim-signing-consumed.staging",
        )
        || exact_wrapped_hex(value, "", 64, ".post-anchor-claim-signing-binding")
        || exact_wrapped_hex(value, ".", 64, ".post-anchor-claim-signing-binding.staging")
        || exact_wrapped_hex(value, "", 64, ".post-anchor-claim-pre-signature")
        || exact_wrapped_hex(value, ".", 64, ".post-anchor-claim-pre-signature.staging")
        || exact_wrapped_hex(value, "", 64, ".funding-consumed")
        || exact_wrapped_hex(value, ".", 64, ".funding-consumed.staging")
        || exact_wrapped_hex(value, "", 64, ".transport-roster")
        || exact_wrapped_hex(value, ".", 64, ".transport-roster.staging")
        || exact_wrapped_hex(value, "", 64, ".transport-identities")
        || exact_wrapped_hex(value, ".", 64, ".transport-identities.staging")
        || exact_wrapped_hex(value, "", 64, ".reservation-lookup")
        || exact_wrapped_hex(value, ".", 64, ".reservation-lookup.staging")
        || exact_wrapped_hex(value, "", 64, ".reservation-abandoned")
        || exact_wrapped_hex(value, ".", 64, ".reservation-abandoned.staging")
        || operational_signing_binding_component(value, false)
        || operational_signing_binding_component(value, true)
        || transport_message_component(value, false, false)
        || transport_message_component(value, true, false)
        || transport_message_component(value, false, true)
        || transport_message_component(value, true, true)
    {
        return Some(ExpectedNodeType::RegularFile);
    }
    None
}

fn operational_signing_binding_component(value: &str, staging: bool) -> bool {
    let prefix = if staging { "." } else { "" };
    let suffix = if staging {
        ".operational-signing-binding.staging"
    } else {
        ".operational-signing-binding"
    };
    let offset = prefix.len();
    let expected = offset + 64 + 1 + 2 + suffix.len();
    value.len() == expected
        && value.starts_with(prefix)
        && value.ends_with(suffix)
        && is_lower_hex(&value[offset..offset + 64], 64)
        && value.as_bytes()[offset + 64] == b'-'
        && matches!(&value[offset + 65..offset + 67], "01" | "02" | "03")
}

fn transport_message_component(value: &str, staging: bool, equivocation: bool) -> bool {
    let prefix = if staging { "." } else { "" };
    let terminal = if equivocation {
        ".equivocation"
    } else {
        ".message"
    };
    let suffix = if staging {
        if equivocation {
            ".equivocation.staging"
        } else {
            ".message.staging"
        }
    } else {
        terminal
    };
    let expected = prefix.len() + 64 + 1 + 64 + 1 + 20 + suffix.len();
    value.len() == expected
        && value.starts_with(prefix)
        && value.ends_with(suffix)
        && is_lower_hex(&value[prefix.len()..prefix.len() + 64], 64)
        && value.as_bytes()[prefix.len() + 64] == b'-'
        && is_lower_hex(&value[prefix.len() + 65..prefix.len() + 129], 64)
        && value.as_bytes()[prefix.len() + 129] == b'-'
        && is_decimal(&value[prefix.len() + 130..prefix.len() + 150], 20)
}

fn session_revision_component(value: &str, staging: bool) -> bool {
    let prefix = if staging { "." } else { "" };
    let suffix = if staging {
        ".session.staging"
    } else {
        ".session"
    };
    let expected = prefix.len() + 64 + 1 + 20 + suffix.len();
    value.len() == expected
        && value.starts_with(prefix)
        && value.ends_with(suffix)
        && is_lower_hex(&value[prefix.len()..prefix.len() + 64], 64)
        && value.as_bytes()[prefix.len() + 64] == b'-'
        && is_decimal(&value[prefix.len() + 65..prefix.len() + 65 + 20], 20)
}

fn collaborative_state_component(value: &str, staging: bool) -> bool {
    let prefix = if staging { "." } else { "" };
    let suffix = if staging { ".staging" } else { "" };
    let Some(inner) = value
        .strip_prefix(prefix)
        .and_then(|inner| inner.strip_suffix(suffix))
    else {
        return false;
    };
    if inner.len() <= 64 {
        return false;
    }
    let (digest, kind) = inner.split_at(64);
    is_lower_hex(digest, 64)
        && matches!(
            kind,
            ".shared-pending"
                | ".bp-nonce"
                | ".bp-round2"
                | ".bp-proof"
                | ".shared-bound"
                | ".shared-pending-retired"
                | ".shared-bound-retired"
                | ".terminal-session"
        )
}

fn exact_wrapped_hex(value: &str, prefix: &str, digits: usize, suffix: &str) -> bool {
    value.len() == prefix.len() + digits + suffix.len()
        && value.starts_with(prefix)
        && value.ends_with(suffix)
        && is_lower_hex(&value[prefix.len()..prefix.len() + digits], digits)
}

fn generation_component(value: &str, staging: bool) -> bool {
    let prefix = if staging {
        ".generation-"
    } else {
        "generation-"
    };
    let suffix = if staging { ".staging" } else { "" };
    decimal_hex_suffix_with_prefix(value, prefix, 20, 64, suffix)
}

fn backup_component(value: &str, staging: bool) -> bool {
    let prefix = if staging { ".backup-" } else { "backup-" };
    let suffix = if staging { ".staging" } else { "" };
    decimal_hex_suffix_with_prefix(value, prefix, 20, 64, suffix)
}

fn decimal_hex_suffix(value: &str, decimal: usize, hex: usize, suffix: &str) -> bool {
    decimal_hex_suffix_with_prefix(value, "", decimal, hex, suffix)
}

fn decimal_hex_suffix_with_prefix(
    value: &str,
    prefix: &str,
    decimal: usize,
    hex: usize,
    suffix: &str,
) -> bool {
    let expected = prefix.len() + decimal + 1 + hex + suffix.len();
    if value.len() != expected || !value.starts_with(prefix) || !value.ends_with(suffix) {
        return false;
    }
    let payload = &value[prefix.len()..value.len() - suffix.len()];
    let Some((left, right)) = payload.split_once('-') else {
        return false;
    };
    is_decimal(left, decimal) && is_lower_hex(right, hex)
}

fn hex_hex_suffix(value: &str, first: usize, second: usize, suffix: &str) -> bool {
    let expected = first + 1 + second + suffix.len();
    if value.len() != expected || !value.ends_with(suffix) {
        return false;
    }
    let payload = &value[..value.len() - suffix.len()];
    let Some((left, right)) = payload.split_once('-') else {
        return false;
    };
    is_lower_hex(left, first) && is_lower_hex(right, second)
}

fn is_decimal(value: &str, exact_len: usize) -> bool {
    value.len() == exact_len && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_lower_hex(value: &str, exact_len: usize) -> bool {
    value.len() == exact_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn map_errno(operation: &'static str, error: Errno) -> LinuxCapabilityError {
    match error {
        Errno::EXIST => LinuxCapabilityError::AlreadyExists,
        Errno::NOENT => LinuxCapabilityError::NotFound,
        Errno::WOULDBLOCK => LinuxCapabilityError::StoreBusy,
        Errno::NOSYS | Errno::INVAL | Errno::XDEV => LinuxCapabilityError::UnsupportedFilesystem,
        _ => LinuxCapabilityError::OperationFailed {
            operation,
            os_code: Some(error.raw_os_error()),
        },
    }
}

fn map_io(operation: &'static str, error: std::io::Error) -> LinuxCapabilityError {
    LinuxCapabilityError::OperationFailed {
        operation,
        os_code: error.raw_os_error(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        path::{Path, PathBuf},
        process::{self, Command},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn create() -> Result<Self, Box<dyn Error>> {
            let base = std::env::temp_dir();
            loop {
                let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let candidate = base.join(format!(
                    "dom-contracts-capability-test-{}-{sequence}",
                    process::id()
                ));
                match fs::create_dir(&candidate) {
                    Ok(()) => {
                        fs::set_permissions(
                            &candidate,
                            fs::Permissions::from_mode(DIRECTORY_MODE),
                        )?;
                        return Ok(Self { path: candidate });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(Box::new(error)),
                }
            }
        }

        fn capability(&self) -> Result<Arc<Dir>, Box<dyn Error>> {
            Ok(Arc::new(Dir::from_std_file(File::open(&self.path)?)))
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn create_root() -> Result<(TestDirectory, RetainedDirectory), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let root = RetainedDirectory::create_under(
            temporary.capability()?,
            ValidatedComponent::operator_selected_root("contracts-store")?,
        )?;
        Ok((temporary, root))
    }

    #[test]
    fn component_registry_rejects_unknown_and_noncanonical_names() {
        assert!(ValidatedComponent::registered("journal").is_ok());
        assert!(ValidatedComponent::registered("0".repeat(210).as_str()).is_ok());
        assert!(ValidatedComponent::registered(
            format!(".{}.tombstone.staging", "a".repeat(210)).as_str()
        )
        .is_ok());
        for invalid in [
            "",
            ".",
            "..",
            "unknown",
            "journal/child",
            "journal\\child",
            "AA.authority",
            "0.authority",
        ] {
            assert_eq!(
                ValidatedComponent::registered(invalid),
                Err(LinuxCapabilityError::InvalidComponent)
            );
        }
        let maximum = format!(".{}.tombstone.staging", "f".repeat(210));
        assert_eq!(maximum.len(), REQUIRED_COMPONENT_LIMIT as usize);
        assert!(ValidatedComponent::registered(&maximum).is_ok());
        assert_eq!(
            ValidatedComponent::registered(&format!("{maximum}x")),
            Err(LinuxCapabilityError::InvalidComponent)
        );
    }

    #[test]
    fn create_no_clobber_persists_and_reopens_exact_bytes() -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = create_root()?;
        let file_name = ValidatedComponent::registered("store-root-identity.bin")?;
        let bytes = b"authenticated test record";
        let mut retained = root.create_immutable_file(&file_name, bytes)?;
        retained.require_exact_bytes(bytes)?;
        assert!(matches!(
            root.create_immutable_file(&file_name, b"replacement"),
            Err(LinuxCapabilityError::AlreadyExists)
        ));
        Ok(())
    }

    #[test]
    fn unsynchronizable_parent_fails_before_mutation() -> Result<(), Box<dyn Error>> {
        let temporary = TestDirectory::create()?;
        let path_only = Arc::new(Dir::open_ambient_dir(
            temporary.path(),
            cap_std::ambient_authority(),
        )?);
        let result = RetainedDirectory::create_under(
            path_only,
            ValidatedComponent::operator_selected_root("must-not-exist")?,
        );
        assert!(matches!(
            result,
            Err(LinuxCapabilityError::OperationFailed {
                operation: "fsync-directory-preflight",
                ..
            })
        ));
        assert!(!temporary.path().join("must-not-exist").exists());
        Ok(())
    }

    #[test]
    fn existing_wrong_mode_and_hard_link_fail_closed() -> Result<(), Box<dyn Error>> {
        let (temporary, root) = create_root()?;
        let name = ValidatedComponent::registered("store-root-identity.bin")?;
        let retained = root.create_immutable_file(&name, b"record")?;
        fs::set_permissions(
            temporary
                .path()
                .join("contracts-store/store-root-identity.bin"),
            fs::Permissions::from_mode(0o640),
        )?;
        assert_eq!(
            retained.revalidate(),
            Err(LinuxCapabilityError::InvalidObject)
        );

        fs::set_permissions(
            temporary
                .path()
                .join("contracts-store/store-root-identity.bin"),
            fs::Permissions::from_mode(FILE_MODE),
        )?;
        fs::hard_link(
            temporary
                .path()
                .join("contracts-store/store-root-identity.bin"),
            temporary.path().join("contracts-store/hard-link-test"),
        )?;
        assert_eq!(
            retained.revalidate(),
            Err(LinuxCapabilityError::InvalidObject)
        );
        Ok(())
    }

    #[test]
    fn symlink_substitution_is_never_followed() -> Result<(), Box<dyn Error>> {
        let (temporary, root) = create_root()?;
        let target = temporary.path().join("outside");
        fs::write(&target, b"not authoritative")?;
        symlink(
            &target,
            temporary
                .path()
                .join("contracts-store/store-root-identity.bin"),
        )?;
        let component = ValidatedComponent::registered("store-root-identity.bin")?;
        assert!(root.open_file(&component, false).is_err());
        Ok(())
    }

    #[test]
    fn no_replace_rename_never_overwrites() -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = create_root()?;
        let staging = ValidatedComponent::registered(".active-vault-generation.staging")?;
        let active = ValidatedComponent::registered("active-vault-generation")?;
        let retained_staging = root.create_immutable_file(&staging, b"first")?;
        root.create_immutable_file(&active, b"existing")?;
        assert_eq!(
            root.rename_no_replace(&staging, &active, &retained_staging),
            Err(LinuxCapabilityError::AlreadyExists)
        );
        let mut active_file = root.open_file(&active, false)?;
        active_file.require_exact_bytes(b"existing")?;
        Ok(())
    }

    #[test]
    fn generation_directory_rename_is_retained_and_never_overwrites() -> Result<(), Box<dyn Error>>
    {
        let (_temporary, root) = create_root()?;
        let final_name = format!("generation-{:020}-{}", 1, "4a".repeat(32));
        let staging_name = format!(".{final_name}.staging");
        let final_component = ValidatedComponent::registered(&final_name)?;
        let staging_component = ValidatedComponent::registered(&staging_name)?;
        let staging = root.create_child_directory(staging_component.clone())?;
        staging.sync()?;
        let published =
            root.rename_generation_no_replace(&staging_component, &final_component, &staging)?;
        published.revalidate()?;
        assert!(root
            .open_child_directory(staging_component.clone())
            .is_err());

        let second_staging = root.create_child_directory(staging_component.clone())?;
        second_staging.sync()?;
        assert!(matches!(
            root.rename_generation_no_replace(
                &staging_component,
                &final_component,
                &second_staging,
            ),
            Err(LinuxCapabilityError::AlreadyExists)
        ));
        second_staging.revalidate()?;
        published.revalidate()?;
        Ok(())
    }

    #[test]
    fn active_pointer_is_the_only_replacing_rename() -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = create_root()?;
        let staging = ValidatedComponent::registered(".active-vault-generation.staging")?;
        let active = ValidatedComponent::registered("active-vault-generation")?;
        root.create_immutable_file(&active, b"old")?;
        let retained_staging = root.create_immutable_file(&staging, b"new")?;
        root.replace_active_pointer(&staging, &active, &retained_staging)?;
        let mut active_file = root.open_file(&active, false)?;
        active_file.require_exact_bytes(b"new")?;

        let unrelated = ValidatedComponent::registered("restore-only-root.bin")?;
        assert_eq!(
            root.replace_active_pointer(&unrelated, &active, &retained_staging),
            Err(LinuxCapabilityError::InvalidComponent)
        );
        Ok(())
    }

    #[test]
    fn restore_publication_moves_only_retained_canonical_objects() -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = create_root()?;
        let transaction = "ab".repeat(16);
        let staging_name = format!(".restore-{transaction}.staging");
        let staging_component = ValidatedComponent::registered(&staging_name)?;
        let staging = root.create_child_directory(staging_component.clone())?;
        let successor = staging
            .create_child_directory(ValidatedComponent::registered("successor-generation")?)?;
        successor.create_immutable_file(
            &ValidatedComponent::registered("generation-core.bin")?,
            b"successor-core",
        )?;
        successor.sync()?;
        let activation =
            staging.create_child_directory(ValidatedComponent::registered("activation")?)?;
        let _staged_active = activation.create_immutable_file(
            &ValidatedComponent::registered("active-generation.bin")?,
            b"successor-active",
        )?;
        activation.sync()?;
        staging.sync()?;

        root.create_immutable_file(
            &ValidatedComponent::registered("active-vault-generation")?,
            b"predecessor-active",
        )?;
        let pending = root.publish_restore_staging_no_replace(&staging_component, &staging)?;
        let retained_successor = pending
            .open_child_directory(ValidatedComponent::registered("successor-generation")?)?;
        let generation_name = format!("generation-{:020}-{}", 2, "cd".repeat(32));
        let activated_generation = root.activate_restore_generation_no_replace(
            &pending,
            &retained_successor,
            &ValidatedComponent::registered(&generation_name)?,
        )?;
        let mut core = activated_generation.open_file(
            &ValidatedComponent::registered("generation-core.bin")?,
            false,
        )?;
        core.require_exact_bytes(b"successor-core")?;

        let retained_activation =
            pending.open_child_directory(ValidatedComponent::registered("activation")?)?;
        let retained_active = retained_activation.open_file(
            &ValidatedComponent::registered("active-generation.bin")?,
            false,
        )?;
        root.activate_restore_pointer(&pending, &retained_activation, &retained_active)?;
        let mut active = root.open_file(
            &ValidatedComponent::registered("active-vault-generation")?,
            false,
        )?;
        active.require_exact_bytes(b"successor-active")?;

        let completed_name = format!("restore-complete-{transaction}");
        let completed = root.retain_completed_restore_no_replace(
            &pending,
            &ValidatedComponent::registered(&completed_name)?,
        )?;
        completed.revalidate()?;
        assert!(root
            .open_child_directory(ValidatedComponent::registered("restore-pending")?)
            .is_err());
        assert!(root.open_child_directory(staging_component).is_err());
        Ok(())
    }

    #[test]
    fn lock_lifetime_blocks_a_second_open_instance() -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = create_root()?;
        let lock_name = ValidatedComponent::registered("store-lock-identity.bin")?;
        root.create_immutable_file(&lock_name, b"lock identity")?;
        let first = root.acquire_lock(&lock_name)?;
        assert!(matches!(
            root.acquire_lock(&lock_name),
            Err(LinuxCapabilityError::StoreBusy)
        ));
        first.revalidate()?;
        drop(first);
        let second = root.acquire_lock(&lock_name)?;
        second.revalidate()?;
        Ok(())
    }

    #[test]
    fn lock_lifetime_blocks_a_second_process() -> Result<(), Box<dyn Error>> {
        let (temporary, root) = create_root()?;
        let lock_name = ValidatedComponent::registered("store-lock-identity.bin")?;
        root.create_immutable_file(&lock_name, b"lock identity")?;
        let retained_lock = root.acquire_lock(&lock_name)?;
        let status = Command::new(std::env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg("runtime::linux::tests::child_observes_busy_lock")
            .env("DOM_CONTRACTS_LOCK_TEST_PARENT", temporary.path())
            .status()?;
        assert!(status.success());
        retained_lock.revalidate()?;
        Ok(())
    }

    #[test]
    fn lock_path_replacement_invalidates_the_retained_authority() -> Result<(), Box<dyn Error>> {
        let (temporary, root) = create_root()?;
        let lock_name = ValidatedComponent::registered("store-lock-identity.bin")?;
        root.create_immutable_file(&lock_name, b"lock identity")?;
        let original = root.acquire_lock(&lock_name)?;

        let lock_path = temporary
            .path()
            .join("contracts-store/store-lock-identity.bin");
        let displaced = temporary.path().join("displaced-lock");
        fs::rename(&lock_path, &displaced)?;
        fs::write(&lock_path, b"lock identity")?;
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(FILE_MODE))?;

        assert_eq!(
            original.revalidate(),
            Err(LinuxCapabilityError::IdentityMismatch)
        );
        let replacement = root.acquire_lock(&lock_name)?;
        replacement.revalidate()?;
        assert_eq!(
            original.revalidate(),
            Err(LinuxCapabilityError::IdentityMismatch)
        );
        Ok(())
    }

    #[test]
    #[ignore = "subprocess helper invoked by lock_lifetime_blocks_a_second_process"]
    fn child_observes_busy_lock() -> Result<(), Box<dyn Error>> {
        let parent_path = std::env::var_os("DOM_CONTRACTS_LOCK_TEST_PARENT")
            .ok_or(LinuxCapabilityError::InvalidComponent)?;
        let parent = Arc::new(Dir::from_std_file(File::open(parent_path)?));
        let root = RetainedDirectory::open_under(
            parent,
            ValidatedComponent::operator_selected_root("contracts-store")?,
        )?;
        let lock_name = ValidatedComponent::registered("store-lock-identity.bin")?;
        assert!(matches!(
            root.acquire_lock(&lock_name),
            Err(LinuxCapabilityError::StoreBusy)
        ));
        Ok(())
    }

    #[test]
    fn verified_unlink_requires_the_retained_identity() -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = create_root()?;
        let component = ValidatedComponent::registered("restore-only-root.bin")?;
        let retained = root.create_immutable_file(&component, b"restore marker")?;
        root.unlink_verified_file(&component, &retained)?;
        assert!(matches!(
            root.open_file(&component, false),
            Err(LinuxCapabilityError::NotFound)
        ));
        Ok(())
    }

    #[test]
    fn verified_unlink_rejects_name_replacement() -> Result<(), Box<dyn Error>> {
        let (temporary, root) = create_root()?;
        let component = ValidatedComponent::registered("restore-only-root.bin")?;
        let retained = root.create_immutable_file(&component, b"original")?;
        let replacement = temporary.path().join("replacement");
        fs::write(&replacement, b"replacement")?;
        fs::set_permissions(&replacement, fs::Permissions::from_mode(FILE_MODE))?;
        fs::rename(
            &replacement,
            temporary
                .path()
                .join("contracts-store/restore-only-root.bin"),
        )?;
        assert_eq!(
            root.unlink_verified_file(&component, &retained),
            Err(LinuxCapabilityError::InvalidObject)
        );
        assert_eq!(
            fs::read(
                temporary
                    .path()
                    .join("contracts-store/restore-only-root.bin")
            )?,
            b"replacement"
        );
        Ok(())
    }

    #[test]
    fn scan_rejects_unknown_entries_and_symlinks() -> Result<(), Box<dyn Error>> {
        let (temporary, root) = create_root()?;
        fs::write(temporary.path().join("contracts-store/unknown"), b"unknown")?;
        fs::set_permissions(
            temporary.path().join("contracts-store/unknown"),
            fs::Permissions::from_mode(FILE_MODE),
        )?;
        assert_eq!(
            root.scan_independent(|_, _| Ok(())),
            Err(LinuxCapabilityError::InvalidComponent)
        );
        fs::remove_file(temporary.path().join("contracts-store/unknown"))?;
        symlink(
            temporary.path(),
            temporary.path().join("contracts-store/journal"),
        )?;
        assert_eq!(
            root.scan_independent(|_, _| Ok(())),
            Err(LinuxCapabilityError::InvalidObject)
        );
        Ok(())
    }

    #[test]
    fn repeated_scans_use_independent_open_file_descriptions() -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = create_root()?;
        for name in ["journal", "tombstones", "nonce-secrets"] {
            root.create_child_directory(ValidatedComponent::registered(name)?)?;
        }
        let mut first = Vec::new();
        root.scan_independent(|name, _identity| {
            first.push(name.to_owned());
            Ok(())
        })?;
        let mut second = Vec::new();
        root.scan_independent(|name, _identity| {
            second.push(name.to_owned());
            Ok(())
        })?;
        first.sort();
        second.sort();
        assert_eq!(first, second);
        assert_eq!(first, ["journal", "nonce-secrets", "tombstones"]);
        Ok(())
    }

    #[test]
    fn registry_valid_flood_is_scanned_with_constant_caller_memory() -> Result<(), Box<dyn Error>> {
        let (temporary, root) = create_root()?;
        let journal = root.create_child_directory(ValidatedComponent::registered("journal")?)?;
        const RECORDS: u64 = 512;
        for sequence in 1..=RECORDS {
            let name = format!("{sequence:020}-{:064x}.journal", sequence);
            let path = temporary.path().join("contracts-store/journal").join(name);
            fs::write(&path, b"x")?;
            fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE))?;
        }

        let mut count = 0_u64;
        journal.scan_independent(|_, _| {
            count = count
                .checked_add(1)
                .ok_or(LinuxCapabilityError::InvalidDirectoryEntry)?;
            Ok(())
        })?;
        assert_eq!(count, RECORDS);
        Ok(())
    }

    #[test]
    fn lexicographic_scan_is_deterministic_without_directory_sized_allocation(
    ) -> Result<(), Box<dyn Error>> {
        let (temporary, root) = create_root()?;
        let journal = root.create_child_directory(ValidatedComponent::registered("journal")?)?;
        for sequence in [9_u64, 1, 12, 3] {
            let name = format!("{sequence:020}-{:064x}.journal", sequence);
            let path = temporary.path().join("contracts-store/journal").join(name);
            fs::write(&path, b"x")?;
            fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE))?;
        }

        let mut observed = Vec::new();
        journal.scan_lexicographic(|name, _| {
            observed.push(name.to_owned());
            Ok(())
        })?;
        assert_eq!(
            observed,
            [1_u64, 3, 9, 12].map(|sequence| format!("{sequence:020}-{:064x}.journal", sequence))
        );
        Ok(())
    }

    #[test]
    fn bounded_read_rejects_oversized_objects_before_parsing() -> Result<(), Box<dyn Error>> {
        let (_temporary, root) = create_root()?;
        let component = ValidatedComponent::registered("store-root-identity.bin")?;
        root.create_immutable_file(&component, b"12345")?;
        assert_eq!(
            root.read_bounded_file(&component, 4),
            Err(LinuxCapabilityError::ExactBytesMismatch)
        );
        assert_eq!(root.read_bounded_file(&component, 5)?, b"12345");
        Ok(())
    }
}
