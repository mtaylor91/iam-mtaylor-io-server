
CREATE TABLE IF NOT EXISTS "users" (
  "user_uuid" UUID PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS "users_emails" (
  "user_uuid" UUID PRIMARY KEY NOT NULL REFERENCES "users" ("user_uuid"),
  "user_email" TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS "groups" (
  "group_uuid" UUID PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS "groups_names" (
  "group_uuid" UUID PRIMARY KEY NOT NULL REFERENCES "groups" ("group_uuid"),
  "group_name" TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS "policies" (
  "policy_uuid" UUID PRIMARY KEY NOT NULL,
  "policy_host" TEXT NOT NULL,
  "policy" JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS "users_groups" (
  "user_uuid" UUID NOT NULL,
  "group_uuid" UUID NOT NULL,
  PRIMARY KEY ("user_uuid", "group_uuid"),
  FOREIGN KEY ("user_uuid") REFERENCES "users" ("user_uuid"),
  FOREIGN KEY ("group_uuid") REFERENCES "groups" ("group_uuid")
);

CREATE TABLE IF NOT EXISTS "users_public_keys" (
  "user_uuid" UUID NOT NULL,
  "public_key" BYTEA NOT NULL,
  "description" TEXT NOT NULL,
  PRIMARY KEY ("user_uuid", "public_key"),
  FOREIGN KEY ("user_uuid") REFERENCES "users" ("user_uuid")
);

CREATE TABLE IF NOT EXISTS "users_policies" (
  "user_uuid" UUID NOT NULL,
  "policy_uuid" UUID NOT NULL,
  PRIMARY KEY ("user_uuid", "policy_uuid"),
  FOREIGN KEY ("user_uuid") REFERENCES "users" ("user_uuid"),
  FOREIGN KEY ("policy_uuid") REFERENCES "policies" ("policy_uuid")
);

CREATE TABLE IF NOT EXISTS "groups_policies" (
  "group_uuid" UUID NOT NULL,
  "policy_uuid" UUID NOT NULL,
  PRIMARY KEY ("group_uuid", "policy_uuid"),
  FOREIGN KEY ("group_uuid") REFERENCES "groups" ("group_uuid"),
  FOREIGN KEY ("policy_uuid") REFERENCES "policies" ("policy_uuid")
);
