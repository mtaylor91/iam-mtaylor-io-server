
CREATE TABLE IF NOT EXISTS "users" (
  "user_uuid" UUID NOT NULL,
  PRIMARY KEY ("user_uuid")
);

CREATE TABLE IF NOT EXISTS "groups" (
  "group_uuid" UUID NOT NULL,
  PRIMARY KEY ("group_uuid")
);

CREATE TABLE IF NOT EXISTS "policies" (
  "policy_uuid" UUID NOT NULL,
  "policy_host" TEXT NOT NULL,
  "policy" JSONB NOT NULL,
  PRIMARY KEY ("policy_uuid")
);

CREATE TABLE IF NOT EXISTS "login_requests" {
  "login_request_uuid" UUID NOT NULL,
  "user_uuid" UUID NOT NULL,
  "public_key" BYTEA NOT NULL,
  "session_uuid" UUID,
  "login_request_expires" TIMESTAMP NOT NULL,
  "login_request_denied" BOOLEAN NOT NULL,
  PRIMARY KEY ("login_request_uuid"),
  FOREIGN KEY ("user_uuid") REFERENCES "users" ("user_uuid") ON DELETE CASCADE
  FOREIGN KEY ("session_uuid") REFERENCES "sessions" ("session_uuid") ON DELETE CASCADE
}

CREATE TABLE IF NOT EXISTS "users_names" (
  "user_uuid" UUID NOT NULL,
  "user_name" TEXT NOT NULL UNIQUE,
  PRIMARY KEY ("user_uuid"),
  FOREIGN KEY ("user_uuid") REFERENCES "users" ("user_uuid") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "users_emails" (
  "user_uuid" UUID NOT NULL,
  "user_email" TEXT NOT NULL UNIQUE,
  PRIMARY KEY ("user_uuid"),
  FOREIGN KEY ("user_uuid") REFERENCES "users" ("user_uuid") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "groups_names" (
  "group_uuid" UUID NOT NULL,
  "group_name" TEXT NOT NULL UNIQUE,
  PRIMARY KEY ("group_uuid"),
  FOREIGN KEY ("group_uuid") REFERENCES "groups" ("group_uuid") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "policies_names" (
  "policy_uuid" UUID NOT NULL,
  "policy_name" TEXT NOT NULL UNIQUE,
  PRIMARY KEY ("policy_uuid"),
  FOREIGN KEY ("policy_uuid") REFERENCES "policies" ("policy_uuid") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "sessions" (
  "session_uuid" UUID NOT NULL,
  "user_uuid" UUID NOT NULL,
  "session_addr" INET NOT NULL,
  "session_token" TEXT NOT NULL,
  "session_expires" TIMESTAMP NOT NULL,
  PRIMARY KEY ("session_uuid"),
  FOREIGN KEY ("user_uuid") REFERENCES "users" ("user_uuid") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "users_groups" (
  "user_uuid" UUID NOT NULL,
  "group_uuid" UUID NOT NULL,
  PRIMARY KEY ("user_uuid", "group_uuid"),
  FOREIGN KEY ("user_uuid") REFERENCES "users" ("user_uuid") ON DELETE CASCADE,
  FOREIGN KEY ("group_uuid") REFERENCES "groups" ("group_uuid") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "users_public_keys" (
  "user_uuid" UUID NOT NULL,
  "public_key" BYTEA NOT NULL,
  "description" TEXT NOT NULL,
  PRIMARY KEY ("user_uuid", "public_key"),
  FOREIGN KEY ("user_uuid") REFERENCES "users" ("user_uuid") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "users_policies" (
  "user_uuid" UUID NOT NULL,
  "policy_uuid" UUID NOT NULL,
  PRIMARY KEY ("user_uuid", "policy_uuid"),
  FOREIGN KEY ("user_uuid") REFERENCES "users" ("user_uuid") ON DELETE CASCADE,
  FOREIGN KEY ("policy_uuid") REFERENCES "policies" ("policy_uuid") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "groups_policies" (
  "group_uuid" UUID NOT NULL,
  "policy_uuid" UUID NOT NULL,
  PRIMARY KEY ("group_uuid", "policy_uuid"),
  FOREIGN KEY ("group_uuid") REFERENCES "groups" ("group_uuid") ON DELETE CASCADE,
  FOREIGN KEY ("policy_uuid") REFERENCES "policies" ("policy_uuid") ON DELETE CASCADE
);
