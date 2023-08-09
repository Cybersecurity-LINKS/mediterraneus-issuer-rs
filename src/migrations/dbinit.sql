CREATE TABLE identity(
    did text PRIMARY KEY,
    privkey bytea NOT NULL
);

CREATE TABLE holder_request(
    vchash text PRIMARY KEY,
    did text NOT NULL,
    request_expiration text NOT NULL,
    vc text NOT NULL
);