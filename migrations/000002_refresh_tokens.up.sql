CREATE TABLE refresh_tokens (
    jti VARCHAR PRIMARY KEY,         -- уникальный ID токена
    user_id UUID NOT NULL,
    family_id UUID NOT NULL,         -- идентификатор цепочки токенов
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false
);