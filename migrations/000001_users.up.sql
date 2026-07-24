CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR UNIQUE NOT NULL,
    email VARCHAR UNIQUE NOT NULL,
    password_hash VARCHAR NOT NULL,
    user_role VARCHAR NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ DEFAULT now()
);