CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username      text        NOT NULL UNIQUE,
    password_hash text        NOT NULL,
    role          text        NOT NULL CHECK (role IN ('USER', 'ADMIN')),
    enabled       boolean     NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE targets (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id           uuid        NOT NULL REFERENCES users (id) ON DELETE RESTRICT,
    name               text        NOT NULL,
    base_url           text        NOT NULL,
    allowed_hosts      jsonb       NOT NULL,
    status             text        NOT NULL CHECK (status IN ('PENDING_VERIFICATION', 'VERIFIED', 'DISABLED')),
    verification_token text        NOT NULL,
    verified_at        timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (owner_id, base_url)
);
CREATE INDEX idx_targets_owner ON targets (owner_id);

CREATE TABLE target_endpoints (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id  uuid        NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
    method     text        NOT NULL CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD')),
    url        text        NOT NULL,
    parameters jsonb       NOT NULL DEFAULT '[]',
    idempotent boolean     NOT NULL DEFAULT false,
    label      text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (target_id, method, url)
);
CREATE INDEX idx_target_endpoints_target ON target_endpoints (target_id);
