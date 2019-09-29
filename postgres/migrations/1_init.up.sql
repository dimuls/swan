CREATE TABLE password_codes (
    role TEXT NOT NULL,
    login TEXT NOT NULL,
    code TEXT NOT NULL,
    created_at TIME WITH TIME ZONE,

    UNIQUE (role, login)
);

CREATE TABLE admins (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT
);

CREATE TABLE categories (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE category_samples (
    category_id BIGINT NOT NULL REFERENCES categories (id) ON DELETE CASCADE,
    text TEXT NOT NULL
);

CREATE TABLE organizations (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    flats_count INT NOT NULL,
    password_hash TEXT
);

CREATE TABLE operators (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    phone TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    name TEXT NOT NULL,
    responsible_categories BIGINT[] NOT NULL
);

CREATE TABLE owners (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    phone TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    name TEXT NOT NULL,
    address TEXT NOT NULL UNIQUE
);

CREATE TABLE requests (
    id BIGSERIAL PRIMARY KEY,
    organization_id BIGINT NOT NULL REFERENCES organizations (id) ON DELETE SET NULL,
    owner_id BIGINT NOT NULL REFERENCES owners (id) ON DELETE SET NULL,
    operator_id BIGINT REFERENCES operators (id) ON DELETE SET NULL,
    category_id BIGINT REFERENCES categories (id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    response TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);
