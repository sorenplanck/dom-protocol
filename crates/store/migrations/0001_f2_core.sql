-- F2 core schema (F2 spec §8.1, DECIDED) — schema version 2 of this store.
-- Neutral by construction: every column is a bounded blob, an integer or a
-- tag. No DOM type, no secret material — `t`, nonces, shares and seeds are
-- forbidden in every one of these tables (spec §18).
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS settlement_terms (
    settlement_id       BLOB PRIMARY KEY CHECK(length(settlement_id)=32),
    session_id          BLOB NOT NULL UNIQUE CHECK(length(session_id)=32),
    terms_hash          BLOB NOT NULL CHECK(length(terms_hash)=32),
    canonical_terms     BLOB NOT NULL,
    created_at_unix_ms  INTEGER NOT NULL,
    UNIQUE(settlement_id, terms_hash)
) STRICT;

CREATE TABLE IF NOT EXISTS settlement_snapshot (
    settlement_id       BLOB PRIMARY KEY REFERENCES settlement_terms(settlement_id),
    revision            INTEGER NOT NULL CHECK(revision >= 0),
    state_tag           INTEGER NOT NULL,
    context_bytes       BLOB NOT NULL,
    last_event_seq      INTEGER NOT NULL CHECK(last_event_seq >= 0),
    updated_at_unix_ms  INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS settlement_journal (
    settlement_id       BLOB NOT NULL REFERENCES settlement_terms(settlement_id),
    seq                 INTEGER NOT NULL CHECK(seq > 0),
    expected_revision   INTEGER NOT NULL,
    resulting_revision  INTEGER NOT NULL,
    event_id            BLOB NOT NULL CHECK(length(event_id)=32),
    event_kind          INTEGER NOT NULL,
    event_bytes         BLOB NOT NULL,
    context_hash        BLOB NOT NULL CHECK(length(context_hash)=32),
    created_at_unix_ms  INTEGER NOT NULL,
    PRIMARY KEY(settlement_id, seq),
    UNIQUE(settlement_id, event_id)
) STRICT;

CREATE TABLE IF NOT EXISTS chain_cursor (
    settlement_id       BLOB NOT NULL REFERENCES settlement_terms(settlement_id),
    chain_id             BLOB NOT NULL CHECK(length(chain_id)=32),
    cursor_bytes         BLOB NOT NULL,
    anchor_height        INTEGER,
    anchor_hash          BLOB CHECK(anchor_hash IS NULL OR length(anchor_hash)=32),
    revision             INTEGER NOT NULL,
    PRIMARY KEY(settlement_id, chain_id)
) STRICT;

CREATE TABLE IF NOT EXISTS observed_evidence (
    settlement_id       BLOB NOT NULL REFERENCES settlement_terms(settlement_id),
    evidence_id         BLOB NOT NULL CHECK(length(evidence_id)=32),
    chain_id             BLOB NOT NULL CHECK(length(chain_id)=32),
    tx_id                BLOB NOT NULL CHECK(length(tx_id)=32),
    event_index          INTEGER NOT NULL,
    block_height         INTEGER NOT NULL,
    block_anchor         BLOB NOT NULL CHECK(length(block_anchor)=32),
    status_tag           INTEGER NOT NULL,
    first_seen_seq       INTEGER NOT NULL,
    PRIMARY KEY(settlement_id, evidence_id)
) STRICT;

CREATE TABLE IF NOT EXISTS durable_outbox (
    settlement_id       BLOB NOT NULL REFERENCES settlement_terms(settlement_id),
    effect_id            BLOB NOT NULL CHECK(length(effect_id)=32),
    source_seq           INTEGER NOT NULL,
    effect_kind          INTEGER NOT NULL,
    payload_bytes        BLOB NOT NULL,
    payload_hash         BLOB NOT NULL CHECK(length(payload_hash)=32),
    status_tag           INTEGER NOT NULL,
    attempts             INTEGER NOT NULL DEFAULT 0,
    lease_until_unix_ms  INTEGER,
    completed_at_unix_ms INTEGER,
    PRIMARY KEY(settlement_id, effect_id)
) STRICT;

CREATE TABLE IF NOT EXISTS terminal_outcome (
    settlement_id       BLOB PRIMARY KEY REFERENCES settlement_terms(settlement_id),
    outcome_tag         INTEGER NOT NULL,
    source_event_id     BLOB NOT NULL CHECK(length(source_event_id)=32),
    finalized_revision  INTEGER NOT NULL,
    created_at_unix_ms  INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS late_evidence (
    settlement_id       BLOB NOT NULL REFERENCES settlement_terms(settlement_id),
    evidence_id         BLOB NOT NULL CHECK(length(evidence_id)=32),
    terminal_tag        INTEGER NOT NULL,
    observed_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY(settlement_id, evidence_id)
) STRICT;
