CREATE TABLE IF NOT EXISTS oauth_user (
    user_id     SERIAL PRIMARY KEY,
    email       VARCHAR(200) NOT NULL UNIQUE,
    password    VARCHAR(500) NOT NULL
);
