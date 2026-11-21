-- oid4vci-issuer-jdbc: everything an issuer keeps between requests, for every tenant. Idempotent; applied at start-up when
-- oid4vci.issuer.store.initialize-schema=true.
--
-- kind  what it is: pre_authorized_code, authorization_code, par, nonce, access_token_claims, credential_offer, dpop_jti,
--       attestation_pop_jti
-- key   SHA-256 (hex) of the tenant-scoped key: codes and nonces are bearer secrets, so they are never stored as such
-- payload AES-256-GCM under oid4vci.issuer.store.encryption-key, bound to kind and key; NULL for nonces and replay records

CREATE TABLE IF NOT EXISTS oid4vci_issuer_entry (
    kind        varchar(32)  NOT NULL,
    key         char(64)     NOT NULL,
    payload     bytea,
    expires_at  timestamptz  NOT NULL,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, key)
);

CREATE INDEX IF NOT EXISTS oid4vci_issuer_entry_expiry ON oid4vci_issuer_entry (expires_at);
