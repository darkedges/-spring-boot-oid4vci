CREATE TABLE IF NOT EXISTS bank_hire (
 id uuid PRIMARY KEY, expected_given text NOT NULL, expected_family text NOT NULL,
 birth_date date NOT NULL, email text NOT NULL, department text NOT NULL,
 status text NOT NULL DEFAULT 'INVITED', invite_hash text UNIQUE,
 invite_expires timestamptz, verified_given text, verified_family text,
 verified_birth date, holder_jwk text, decision_reason text,
 reviewer text, reviewed_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bank_audit (
 id bigserial PRIMARY KEY, hire_id uuid NOT NULL REFERENCES bank_hire(id),
 action text NOT NULL, actor text NOT NULL, occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bank_presentation (
 id text PRIMARY KEY, nonce text NOT NULL, hire_id uuid REFERENCES bank_hire(id),
 browser_secret_hash text NOT NULL, expires_at timestamptz NOT NULL,
 complete boolean NOT NULL DEFAULT false, staff_id uuid
);
ALTER TABLE bank_hire ADD COLUMN IF NOT EXISTS issued_credential text;
ALTER TABLE bank_hire ADD COLUMN IF NOT EXISTS revocation_reason text;
ALTER TABLE bank_hire ADD COLUMN IF NOT EXISTS revoked_by text;
ALTER TABLE bank_hire ADD COLUMN IF NOT EXISTS revoked_at timestamptz;
ALTER TABLE bank_audit ADD COLUMN IF NOT EXISTS reason text;
ALTER TABLE bank_hire ADD COLUMN IF NOT EXISTS previous_hire_id uuid REFERENCES bank_hire(id);
CREATE UNIQUE INDEX IF NOT EXISTS bank_hire_one_followup ON bank_hire(previous_hire_id) WHERE previous_hire_id IS NOT NULL;

ALTER TABLE bank_hire ADD COLUMN IF NOT EXISTS passport_check_after timestamptz;

-- The Journey API (Authr): which front end started a presentation, and when its result was taken (once).
ALTER TABLE bank_presentation ADD COLUMN IF NOT EXISTS channel text NOT NULL DEFAULT 'portal';
ALTER TABLE bank_presentation ADD COLUMN IF NOT EXISTS consumed_at timestamptz;
ALTER TABLE bank_audit ADD COLUMN IF NOT EXISTS channel text;
-- An opened invitation, as a short-lived opaque reference (only its hash is kept). One live reference per attempt.
CREATE TABLE IF NOT EXISTS bank_applicant_ref (
 ref_hash text PRIMARY KEY, hire_id uuid NOT NULL REFERENCES bank_hire(id),
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS bank_applicant_ref_hire ON bank_applicant_ref(hire_id);
