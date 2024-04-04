--
-- THIS IS THE SQL REQUIRED TO SET UP THE LOGIN SERVER DATABASE
--
-- YOU SHOULD CHANGE THE USER PASSWORD FURTHER DOWN...
--

-- create a database for the login server
-- don't forget to connect to it before executing any other SQL
CREATE DATABASE "psflogin";


-- LOGIN SERVER DB

-- create tables
CREATE TABLE IF NOT EXISTS "account" (
    "id" SERIAL PRIMARY KEY,
    "username" VARCHAR(64) NOT NULL UNIQUE,
    "password" VARCHAR(60) NOT NULL,
    "created_at" TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "login" (
    "id" SERIAL PRIMARY KEY,
    "account_id" INT4 NOT NULL,
    "ip" VARCHAR(15) NOT NULL,
    "port" INT NOT NULL,
    "login_at" TIMESTAMP NOT NULL DEFAULT NOW()

    CONSTRAINT "login_port_check" CHECK("port" BETWEEN 1024 AND 65535), -- clients can not connect from privileged ports

    CONSTRAINT "login_account_id_account_fkey" FOREIGN KEY ("account_id") REFERENCES "account"("id") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "database" (
    "id" SERIAL PRIMARY KEY,
    "host" TEXT NOT NULL,
    "port" INT NOT NULL,
    "user" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "database" TEXT NOT NULL,

    CONSTRAINT "database_port_check" CHECK("port" BETWEEN 1 AND 65535), -- servers can run on privileged ports, psql is 54321 by default

    -- enforce unique combination
    CONSTRAINT "database_host_port_database_unique_idx" UNIQUE ("host", "port", "database")
);

CREATE TABLE IF NOT EXISTS "world" (
    "id" SERIAL PRIMARY KEY,
    "name" VARCHAR(32) NOT NULL UNIQUE,
    "location" INT2 NOT NULL DEFAULT 0, -- Internal
    "status" INT2 NOT NULL DEFAULT 0, -- UP
    "type" INT4 NOT NULL DEFAULT 1, -- Development
    "need_faction" INT2 NOT NULL DEFAULT 3, -- none
    "database" INT4 NOT NULL,
    "ip" VARCHAR(15) NOT NULL,
    "port" INT NOT NULL,

    CONSTRAINT "database_location_check" CHECK("location" BETWEEN 0 AND 4),
    CONSTRAINT "database_status_check" CHECK("status" BETWEEN 0 AND 3),
    CONSTRAINT "database_type_check" CHECK("type" BETWEEN 0 AND 4),
    CONSTRAINT "database_need_faction_check" CHECK("need_faction" BETWEEN 0 AND 3),

    CONSTRAINT "world_database_database_fkey" FOREIGN KEY ("database") REFERENCES "database"("id") ON DELETE RESTRICT
);

-- add login server user
CREATE USER "psflogin" WITH PASSWORD 'psflogin';  -- change this

-- grant login server user permissions to the tables
GRANT USAGE ON SCHEMA public TO psflogin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO psflogin;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO psflogin;
GRANT INSERT ON TABLE login TO psflogin;

--
-- SAMPLE SERVER
--
INSERT INTO "database" ("host", "port", "user", "password", "database")
VALUES
    ('127.0.0.1', 5432, 'psflogin', 'psflogin', 'psforever');

INSERT INTO "world" ("name", "location", "status", "type", "need_faction", "database", "ip", "port")
VALUES
    ('TestServer', 4, 0, 3, 1, 1, '127.0.0.1', 51001);
--
