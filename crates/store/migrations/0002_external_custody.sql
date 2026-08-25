ALTER TABLE durable_outbox
ADD COLUMN dispatch_class INTEGER NOT NULL DEFAULT 0
CHECK(dispatch_class IN (0, 1));

ALTER TABLE durable_outbox
ADD COLUMN external_tx_id BLOB
CHECK(external_tx_id IS NULL OR length(external_tx_id) = 32);

CREATE INDEX durable_outbox_dispatch_ready
ON durable_outbox(status_tag, dispatch_class, lease_until_unix_ms, source_seq);
