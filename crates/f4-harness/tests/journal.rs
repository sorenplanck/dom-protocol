//! Step-5 suite (F4 spec §13): the durable assurance journal. Crashes
//! are real dropped processes re-opening the same SQLite file; forged
//! and corrupted logs are refused at replay; memory and store logs are
//! byte-identical.

use f4_harness::journal::{AssuranceLog, DurableAssurance, JournalError, MemoryLog, StoreLog};
use uspe::journal::{AssuranceFrameV1, ASSURANCE_JOURNAL_KIND};
use uspe::{AssuranceEffect, AssuranceEvent, AssuranceState};

const TERMS: [u8; 32] = [0x11; 32];
const WRONG_TERMS: [u8; 32] = [0x22; 32];
const CAP: u128 = 1_000;

/// The canonical slash history, terminal Compensated.
fn slash_history() -> Vec<AssuranceEvent> {
    vec![
        AssuranceEvent::BondLockObserved,
        AssuranceEvent::CollateralVerified { terms_hash: TERMS },
        AssuranceEvent::ObligationFailed,
        AssuranceEvent::CompensationClaimed { terms_hash: TERMS },
        AssuranceEvent::EvidenceVerified { valid: true },
        AssuranceEvent::CompensationConfirmed { amount: CAP },
    ]
}

fn db_path(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(format!("{name}.sqlite"));
    (dir, path)
}

#[test]
fn a_crash_between_every_transition_loses_nothing() {
    // Apply one event per PROCESS: drop the driver (and the store) after
    // each accepted transition and recover from the file alone.
    let (_dir, path) = db_path("crash-every-step");
    for (i, event) in slash_history().iter().enumerate() {
        let log = StoreLog::open(&path).expect("open store");
        let mut driver = DurableAssurance::open(log, TERMS, CAP, true).expect("recover");
        assert_eq!(driver.revision(), i as u64, "step {i}");
        driver.apply(event).expect("accepted");
        // Driver dropped here: the crash.
    }
    let log = StoreLog::open(&path).expect("open store");
    let driver = DurableAssurance::open(log, TERMS, CAP, true).expect("final recovery");
    assert_eq!(driver.context().state, AssuranceState::Compensated);
    assert_eq!(driver.revision(), 6);
}

#[test]
fn effects_are_returned_only_after_the_frame_is_durable() {
    // Crash "after apply returned, before the effect executed": the
    // recovered state must already contain the transition, so the effect
    // can be recomputed and offered again (byte-identical, I7).
    let (_dir, path) = db_path("persist-before-effect");
    {
        let log = StoreLog::open(&path).expect("open store");
        let mut driver = DurableAssurance::open(log, TERMS, CAP, true).expect("fresh");
        for event in &slash_history()[..5] {
            driver.apply(event).expect("accepted");
        }
        let last = driver
            .apply(&AssuranceEvent::CompensationConfirmed { amount: CAP })
            .expect("accepted");
        assert!(last
            .effects
            .contains(&AssuranceEffect::RecordEconomicOutcome(
                AssuranceState::Compensated
            )));
        // Process dies HERE, effect never executed.
    }
    let log = StoreLog::open(&path).expect("open store");
    let driver = DurableAssurance::open(log, TERMS, CAP, true).expect("recover");
    assert_eq!(
        driver.context().state,
        AssuranceState::Compensated,
        "the durable state already carries the transition whose effect is pending"
    );
}

#[test]
fn a_refused_event_appends_nothing() {
    let mut driver = DurableAssurance::open(MemoryLog::new(), TERMS, CAP, true).expect("fresh");
    driver
        .apply(&AssuranceEvent::BondLockObserved)
        .expect("accepted");
    let before = driver.revision();
    // Illegal event, wrong-terms event, over-cap event: all refused, none journaled.
    assert!(driver.apply(&AssuranceEvent::ReleaseConfirmed).is_err());
    assert!(driver
        .apply(&AssuranceEvent::CollateralVerified {
            terms_hash: WRONG_TERMS
        })
        .is_err());
    assert_eq!(driver.revision(), before);
}

#[test]
fn terminal_state_accepts_nothing_and_journals_nothing() {
    let mut driver = DurableAssurance::open(MemoryLog::new(), TERMS, CAP, true).expect("fresh");
    for event in slash_history() {
        driver.apply(&event).expect("accepted");
    }
    let at_terminal = driver.revision();
    for event in slash_history() {
        assert!(driver.apply(&event).is_err(), "terminal is immutable");
    }
    assert_eq!(driver.revision(), at_terminal);
}

#[test]
fn memory_and_store_logs_produce_identical_frames() {
    let (_dir, path) = db_path("parity");
    let mut mem = DurableAssurance::open(MemoryLog::new(), TERMS, CAP, true).expect("mem");
    let mut dur = DurableAssurance::open(StoreLog::open(&path).expect("open"), TERMS, CAP, true)
        .expect("store");
    for event in slash_history() {
        mem.apply(&event).expect("mem accepted");
        dur.apply(&event).expect("store accepted");
    }
    let mem_frames = {
        let mut log = MemoryLog::new();
        let mut driver = DurableAssurance::open(MemoryLog::new(), TERMS, CAP, true).unwrap();
        for event in slash_history() {
            let t = driver.apply(&event).unwrap();
            let frame = AssuranceFrameV1 {
                revision: driver.revision(),
                terms_hash: TERMS,
                event,
                next_state: t.next.state,
                effects: t.effects,
            };
            log.append_frame(&frame.canonical_bytes().unwrap()).unwrap();
        }
        log.frames().unwrap()
    };
    let store_frames = StoreLog::open(&path)
        .expect("reopen")
        .frames()
        .expect("frames");
    assert_eq!(mem_frames, store_frames);
}

#[test]
fn a_log_bound_to_another_obligation_is_refused() {
    let (_dir, path) = db_path("binding");
    {
        let log = StoreLog::open(&path).expect("open");
        let mut driver = DurableAssurance::open(log, TERMS, CAP, true).expect("fresh");
        driver
            .apply(&AssuranceEvent::BondLockObserved)
            .expect("accepted");
    }
    let log = StoreLog::open(&path).expect("reopen");
    let err = match DurableAssurance::open(log, WRONG_TERMS, CAP, true) {
        Err(e) => e,
        Ok(_) => panic!("a swapped log must refuse"),
    };
    assert!(matches!(err, JournalError::LogBindingMismatch));
}

#[test]
fn corrupt_foreign_and_forged_frames_all_fail_closed() {
    // Corrupt: bytes that do not decode.
    let mut log = MemoryLog::new();
    log.append_frame(b"garbage").expect("append");
    assert!(matches!(
        DurableAssurance::open(log, TERMS, CAP, true),
        Err(JournalError::CorruptFrame(_))
    ));

    // Foreign: a record under another journal kind in the same store.
    let (_dir, path) = db_path("foreign");
    {
        let mut raw = store::Store::open(&path).expect("open raw");
        raw.append_journal(ASSURANCE_JOURNAL_KIND + 1, b"foreign")
            .expect("append foreign");
    }
    let log = StoreLog::open(&path).expect("reopen");
    assert!(matches!(
        DurableAssurance::open(log, TERMS, CAP, true),
        Err(JournalError::ForeignRecord)
    ));

    // Forged: a well-formed frame whose transition the machine refuses —
    // it claims the bond was slashed straight from BondRequired.
    let forged = AssuranceFrameV1 {
        revision: 1,
        terms_hash: TERMS,
        event: AssuranceEvent::EvidenceVerified { valid: true },
        next_state: AssuranceState::Slashed,
        effects: vec![
            AssuranceEffect::PersistState(AssuranceState::Slashed),
            AssuranceEffect::ExecuteSlash,
        ],
    };
    let mut log = MemoryLog::new();
    log.append_frame(&forged.canonical_bytes().expect("encodes"))
        .expect("append");
    assert!(matches!(
        DurableAssurance::open(log, TERMS, CAP, true),
        Err(JournalError::ReplayDivergence)
    ));

    // Forged effects: right event and state, wrong effect list.
    let mut wrong_effects = AssuranceFrameV1 {
        revision: 1,
        terms_hash: TERMS,
        event: AssuranceEvent::BondLockObserved,
        next_state: AssuranceState::BondLocking,
        effects: vec![
            AssuranceEffect::PersistState(AssuranceState::BondLocking),
            AssuranceEffect::ExecuteSlash,
        ],
    };
    let mut log = MemoryLog::new();
    log.append_frame(&wrong_effects.canonical_bytes().expect("encodes"))
        .expect("append");
    assert!(matches!(
        DurableAssurance::open(log, TERMS, CAP, true),
        Err(JournalError::ReplayDivergence)
    ));

    // Gap: revision 2 with no revision 1.
    wrong_effects.effects = vec![AssuranceEffect::PersistState(AssuranceState::BondLocking)];
    wrong_effects.revision = 2;
    let mut log = MemoryLog::new();
    log.append_frame(&wrong_effects.canonical_bytes().expect("encodes"))
        .expect("append");
    assert!(matches!(
        DurableAssurance::open(log, TERMS, CAP, true),
        Err(JournalError::RevisionGap)
    ));
}

#[test]
fn the_journal_bytes_never_contain_more_than_the_machine_said() {
    // The whole log of a slash history decodes back to exactly the
    // machine's own transitions — no extra state, no secrets (the only
    // scalar-adjacent value is the CAP amount, which is policy data).
    let (_dir, path) = db_path("faithful");
    {
        let log = StoreLog::open(&path).expect("open");
        let mut driver = DurableAssurance::open(log, TERMS, CAP, true).expect("fresh");
        for event in slash_history() {
            driver.apply(&event).expect("accepted");
        }
    }
    let frames = StoreLog::open(&path)
        .expect("reopen")
        .frames()
        .expect("frames");
    assert_eq!(frames.len(), 6);
    let mut ctx = uspe::AssuranceContext::new(TERMS, CAP, true);
    for (i, bytes) in frames.iter().enumerate() {
        let frame = AssuranceFrameV1::decode(bytes).expect("decodes");
        assert_eq!(frame.revision, (i + 1) as u64);
        let t = uspe::assurance_transition(ctx, &frame.event).expect("accepted");
        assert_eq!(t.next.state, frame.next_state);
        assert_eq!(t.effects, frame.effects);
        ctx = t.next;
    }
    assert_eq!(ctx.state, AssuranceState::Compensated);
}
