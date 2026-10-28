CREATE TABLE outbox_events (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_id    uuid        NOT NULL,
    topic           text        NOT NULL,
    message_key     text        NOT NULL,
    payload         jsonb       NOT NULL,
    headers         jsonb       NOT NULL,
    status          text        NOT NULL CHECK (status IN ('PENDING', 'SENT')),
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz
);
CREATE INDEX idx_outbox_pending ON outbox_events (next_attempt_at) WHERE status = 'PENDING';

CREATE TABLE processed_messages (
    message_id   uuid PRIMARY KEY,
    consumer     text        NOT NULL,
    processed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id     uuid REFERENCES users (id) ON DELETE SET NULL,
    action       text        NOT NULL,
    subject_type text,
    subject_id   uuid,
    details      jsonb,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_events_created ON audit_events (created_at DESC);
