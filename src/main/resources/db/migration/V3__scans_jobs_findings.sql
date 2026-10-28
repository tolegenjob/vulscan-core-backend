CREATE TABLE scans (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id        uuid        NOT NULL REFERENCES targets (id) ON DELETE RESTRICT,
    policy_id        uuid        NOT NULL REFERENCES scan_policies (id) ON DELETE RESTRICT,
    started_by       uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    status           text        NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLING', 'CANCELLED')),
    cancel_requested boolean     NOT NULL DEFAULT false,
    correlation_id   uuid        NOT NULL,
    config           jsonb       NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    finished_at      timestamptz
);
CREATE INDEX idx_scans_user_created ON scans (started_by, created_at DESC);
CREATE INDEX idx_scans_active ON scans (status) WHERE status IN ('PENDING', 'RUNNING', 'CANCELLING');

CREATE TABLE scan_jobs (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id          uuid        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    module_type      text        NOT NULL CHECK (module_type IN ('XSS', 'SQLI', 'IDOR')),
    status           text        NOT NULL CHECK (status IN ('PENDING', 'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
    attempt          integer     NOT NULL DEFAULT 1,
    worker_id        text,
    lease_expires_at timestamptz,
    deadline_at      timestamptz NOT NULL,
    queued_at        timestamptz,
    started_at       timestamptz,
    finished_at      timestamptz,
    requests_sent    integer     NOT NULL DEFAULT 0,
    endpoints_done   integer     NOT NULL DEFAULT 0,
    error_code       text,
    error_message    text,
    result_integrity text        NOT NULL DEFAULT 'OK' CHECK (result_integrity IN ('OK', 'INCOMPLETE')),
    stats            jsonb,
    UNIQUE (scan_id, module_type)
);
CREATE INDEX idx_scan_jobs_status_lease ON scan_jobs (status, lease_expires_at);
CREATE INDEX idx_scan_jobs_status_queued ON scan_jobs (status, queued_at);

CREATE TABLE findings (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id             uuid        NOT NULL REFERENCES scan_jobs (id) ON DELETE CASCADE,
    scan_id            uuid        NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    target_id          uuid        NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    module_type        text        NOT NULL CHECK (module_type IN ('XSS', 'SQLI', 'IDOR')),
    vuln_type          text        NOT NULL CHECK (vuln_type IN ('XSS_REFLECTED', 'XSS_STORED', 'SQLI_ERROR_BASED', 'SQLI_BOOLEAN_BASED', 'SQLI_TIME_BASED', 'IDOR_HORIZONTAL', 'IDOR_VERTICAL')),
    verdict            text        NOT NULL CHECK (verdict IN ('SUSPECTED', 'LIKELY', 'CONFIRMED')),
    severity           text        NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence         smallint    NOT NULL CHECK (confidence BETWEEN 1 AND 99),
    fingerprint        varchar(64) NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    endpoint_id        uuid,
    method             text        NOT NULL,
    url                text        NOT NULL,
    parameter_name     text,
    parameter_location text,
    title              text        NOT NULL,
    summary            text        NOT NULL,
    recommendation     text        NOT NULL,
    cwe                text        NOT NULL,
    details            jsonb       NOT NULL,
    evidence           jsonb       NOT NULL,
    triage_status      text        NOT NULL DEFAULT 'OPEN' CHECK (triage_status IN ('OPEN', 'FALSE_POSITIVE', 'FIXED')),
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (job_id, fingerprint)
);
CREATE INDEX idx_findings_scan_severity ON findings (scan_id, severity, created_at DESC);
CREATE INDEX idx_findings_target_triage ON findings (target_id, triage_status);
CREATE INDEX idx_findings_vuln_type ON findings (vuln_type);
CREATE INDEX idx_findings_fingerprint ON findings (fingerprint);
