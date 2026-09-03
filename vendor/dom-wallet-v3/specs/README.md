# DOM Wallet V3 Specifications

**Owner:** Soren Planck

| Specification | Status | First pass | Cross-review verdict | Review blockers |
|---|---|---|---|---|
| [0000 Design Principles](0000_DESIGN_PRINCIPLES.md) | REVIEW | Foundation | CONFIRMED_CONSISTENT | None |
| [0001 Threat Model](0001_THREAT_MODEL.md) | REVIEW | Complete | CONFIRMED_CONSISTENT | None |
| [0002 Wallet State Model](0002_WALLET_STATE_MODEL.md) | REVIEW | Complete | CONFIRMED_CONFLICT_RESOLVED | None |
| [0003 Transaction Lifecycle](0003_TRANSACTION_LIFECYCLE.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | Engineering detail completion; no external-audit blocker |
| [0004 Storage and Atomicity](0004_STORAGE_ATOMICITY.md) | REVIEW | Complete | CONFIRMED_CONFLICT_RESOLVED | None |
| [0005 ChainSource and Synchronization](0005_CHAIN_SOURCE_AND_SYNC.md) | REVIEW | Complete | CONFIRMED_CONFLICT_RESOLVED | None |
| [0006 Reorganization and Rollback](0006_REORG_AND_ROLLBACK.md) | REVIEW | Complete | CONFIRMED_CONFLICT_RESOLVED | None |
| [0007 Key Derivation and Secrets](0007_KEY_DERIVATION_AND_SECRETS.md) | DRAFT | Complete | CONFIRMED_CONSISTENT | Engineering detail completion; no external-audit blocker |
| [0008 Backup and Recovery](0008_BACKUP_AND_RECOVERY.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | Engineering detail completion; no external-audit blocker |
| [0009 Economic Rules](0009_ECONOMIC_RULES.md) | REVIEW | Complete | CONFIRMED_CONFLICT_RESOLVED | None |
| [0010 API and Transport Security](0010_API_AND_TRANSPORT_SECURITY.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | Engineering detail completion; no external-audit blocker |
| [0011 Migration from V2](0011_MIGRATION_FROM_V2.md) | DRAFT | Complete | CONFIRMED_CONSISTENT | Engineering detail completion; no external-audit blocker |
| [0012 Testing and Assurance](0012_TESTING_AND_ASSURANCE.md) | REVIEW | Complete | CONFIRMED_CONFLICT_RESOLVED | None |

Required dependency order: Threat Model -> Wallet State Model -> Storage and Atomicity -> ChainSource and Synchronization -> Reorganization and Rollback -> Transaction Lifecycle -> Key Derivation and Secrets -> Backup and Recovery -> Economic Rules -> API and Transport Security -> Migration from V2 -> Testing and Assurance.

Owner-approved StableView Option C and Owner-selected Secret-Domain Option A result: 8 specifications in REVIEW, 5 specifications remaining DRAFT, 30 effective RESOLVED decisions, 0 effective BLOCKING decisions, and 0 effective HIGH blockers. DEC-STABLE-VIEW is resolved by the ScanTarget WALLET POLICY in 0005; DEC-V3-SECRET-DOMAINS is resolved at architecture-policy level by Hardened DOM Wallet Continuity and open community review. The five DRAFT documents remain incomplete engineering documents, not external-audit blockers. Gate 1 is IN PROGRESS as a specification-completion tracker only; implementation authorization is recorded in [the mainnet and community review policy](../docs/MAINNET_AND_COMMUNITY_REVIEW_POLICY.md).
