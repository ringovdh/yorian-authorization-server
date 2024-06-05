CREATE TABLE IF NOT EXISTS user_role (
    user_id int NOT NULL,
    role_id int NOT NULL,
    CONSTRAINT role_fk FOREIGN KEY (role_id) REFERENCES role (role_id),
    CONSTRAINT user_fk FOREIGN KEY (user_id) REFERENCES oauth_user (user_id)
);
