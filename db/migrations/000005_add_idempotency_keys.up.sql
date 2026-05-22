CREATE TABLE "idempotency_keys" (
    "id" VARCHAR(255) PRIMARY KEY,
    "user_id" UUID NOT NULL,
    "response_code" INT NOT NULL,
    "response_body" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX ON "idempotency_keys" ("created_at");