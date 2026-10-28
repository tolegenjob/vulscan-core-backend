CREATE TABLE scan_policies (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text        NOT NULL UNIQUE,
    limits     jsonb       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE test_identities (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id        uuid        NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    label            text        NOT NULL,
    role             text        NOT NULL,
    auth_type        text        NOT NULL CHECK (auth_type IN ('FORM_LOGIN', 'BEARER_STATIC', 'COOKIE_STATIC', 'HEADER_STATIC', 'JSON_LOGIN')),
    auth_config      jsonb       NOT NULL,
    secret_encrypted bytea       NOT NULL,
    key_version      integer     NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (target_id, label)
);

CREATE TABLE resource_access_rules (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id         uuid  NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    endpoint_id       uuid  NOT NULL REFERENCES target_endpoints (id) ON DELETE CASCADE,
    id_parameter      jsonb NOT NULL,
    id_value          text  NOT NULL,
    owner_identity_id uuid  NOT NULL REFERENCES test_identities (id) ON DELETE CASCADE,
    sensitivity       text  NOT NULL CHECK (sensitivity IN ('LOW', 'MEDIUM', 'HIGH')),
    owner_markers     jsonb NOT NULL,
    access            jsonb NOT NULL
);
CREATE INDEX idx_resource_access_rules_target ON resource_access_rules (target_id);
