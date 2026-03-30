-- name: CreateIdempotencyKey :one
INSERT INTO idempotency_keys (
    id, user_id, response_code, response_body
) VALUES (
    $1, $2, $3, $4
) RETURNING *;

-- name: GetIdempotencyKey :one
SELECT * FROM idempotency_keys
WHERE id = $1 AND user_id = $2;