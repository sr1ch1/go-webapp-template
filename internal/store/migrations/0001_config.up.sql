-- Runtime Configuration: application settings changeable while the app runs.
CREATE TABLE config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO config (key, value) VALUES
    ('site_name', 'Web App Template'),
    ('motd', 'Welcome.');
