-- Gyges' tables in a key's wallet.sqlite (docs/architecture.md Data model §5). Run once by
-- the external migration in db/mod.rs. The CHECK lists must match the
-- enums' as_str() spellings; db tests insert every variant to keep them in
-- step.

-- ZIP 320 transfers (§5.1): both signed steps, so the daemon can finish a
-- transfer after a restart without signing again.
CREATE TABLE ext_gyges_tex_queue (
    step1_txid       BLOB NOT NULL PRIMARY KEY,
    step2_txid       BLOB NOT NULL,
    proposal         BLOB NOT NULL,
    step1_raw        BLOB NOT NULL,
    step2_raw        BLOB NOT NULL,
    ephemeral_addr   TEXT NOT NULL,
    recipient        TEXT NOT NULL,
    amount           INTEGER NOT NULL,
    expiry_height    INTEGER NOT NULL,
    state            TEXT NOT NULL CHECK (state IN (
                         'built', 'step1_broadcast', 'step2_broadcast',
                         'step1_mined', 'step2_mined', 'step2_failed',
                         'expired', 'failed', 'aborted')),
    created_at       INTEGER NOT NULL,
    last_attempt_at  INTEGER,
    attempts         INTEGER NOT NULL DEFAULT 0,
    last_error       TEXT
);
CREATE INDEX ext_gyges_tex_queue_state ON ext_gyges_tex_queue (state);

-- Signing sessions that outlive a connection (§5.2): PCZT files, and
-- Keystone sessions with their device-side half in the nullable columns.
CREATE TABLE ext_gyges_signing_sessions (
    session_id     TEXT NOT NULL PRIMARY KEY,
    protocol       TEXT NOT NULL CHECK (protocol IN ('keystone-batch', 'keystone-pczt', 'file')),
    status         TEXT NOT NULL CHECK (status IN (
                       'awaiting-signature', 'signed', 'broadcast', 'aborted', 'expired')),
    created_at     INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    proposal       BLOB NOT NULL,
    expected       BLOB NOT NULL,
    txid           BLOB,
    last_error     TEXT,
    pczt           BLOB,
    payload        BLOB,
    request_id     BLOB,
    via_tor        INTEGER,
    expiry_height  INTEGER,
    -- A Keystone session always carries its device-side half; a file one never does.
    CHECK ((protocol = 'file') = (pczt IS NULL)),
    CHECK ((pczt IS NULL) = (payload IS NULL)
       AND (pczt IS NULL) = (via_tor IS NULL)
       AND (pczt IS NULL) = (expiry_height IS NULL))
);
CREATE INDEX ext_gyges_signing_sessions_status
    ON ext_gyges_signing_sessions (status, expires_at);

-- Labels given with `address new --label` (§5.3).
CREATE TABLE ext_gyges_address_labels (
    address     TEXT NOT NULL PRIMARY KEY,
    label       TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
