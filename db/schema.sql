
CREATE TABLE IF NOT EXISTS "user_emails" (
  "user_email" TEXT PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS "user_uuids" (
  "user_uuid" UUID PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS "group_names" (
  "group_name" TEXT PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS "group_uuids" (
  "group_uuid" UUID PRIMARY KEY NOT NULL
);

CREATE TABLE IF NOT EXISTS "policies" (
  "policy_uuid" UUID PRIMARY KEY NOT NULL,
  "policy" JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS "user_email_group_names" (
  "user_email" TEXT NOT NULL,
  "group_name" TEXT NOT NULL,
  PRIMARY KEY ("user_email", "group_name"),
  FOREIGN KEY ("user_email") REFERENCES "user_emails" ("user_email"),
  FOREIGN KEY ("group_name") REFERENCES "group_names" ("group_name")
);

CREATE TABLE IF NOT EXISTS "user_email_group_uuids" (
  "user_email" TEXT NOT NULL,
  "group_uuid" UUID NOT NULL,
  PRIMARY KEY ("user_email", "group_uuid"),
  FOREIGN KEY ("user_email") REFERENCES "user_emails" ("user_email"),
  FOREIGN KEY ("group_uuid") REFERENCES "group_uuids" ("group_uuid")
);

CREATE TABLE IF NOT EXISTS "user_uuid_group_names" (
  "user_uuid" UUID NOT NULL,
  "group_name" TEXT NOT NULL,
  PRIMARY KEY ("user_uuid", "group_name"),
  FOREIGN KEY ("user_uuid") REFERENCES "user_uuids" ("user_uuid"),
  FOREIGN KEY ("group_name") REFERENCES "group_names" ("group_name")
);

CREATE TABLE IF NOT EXISTS "user_uuid_group_uuids" (
  "user_uuid" UUID NOT NULL,
  "group_uuid" UUID NOT NULL,
  PRIMARY KEY ("user_uuid", "group_uuid"),
  FOREIGN KEY ("user_uuid") REFERENCES "user_uuids" ("user_uuid"),
  FOREIGN KEY ("group_uuid") REFERENCES "group_uuids" ("group_uuid")
);

CREATE TABLE IF NOT EXISTS "user_email_public_keys" (
  "user_email" TEXT NOT NULL,
  "public_key" BYTEA NOT NULL,
  "description" TEXT NOT NULL,
  PRIMARY KEY ("user_email"),
  FOREIGN KEY ("user_email") REFERENCES "user_emails" ("user_email")
);

CREATE TABLE IF NOT EXISTS "user_uuid_public_keys" (
  "user_uuid" UUID NOT NULL,
  "public_key" BYTEA NOT NULL,
  "description" TEXT NOT NULL,
  PRIMARY KEY ("user_uuid"),
  FOREIGN KEY ("user_uuid") REFERENCES "user_uuids" ("user_uuid")
);

CREATE TABLE IF NOT EXISTS "user_email_policies" (
  "user_email" TEXT NOT NULL,
  "policy_uuid" UUID NOT NULL,
  PRIMARY KEY ("user_email", "policy_uuid"),
  FOREIGN KEY ("user_email") REFERENCES "user_emails" ("user_email"),
  FOREIGN KEY ("policy_uuid") REFERENCES "policies" ("policy_uuid")
);

CREATE TABLE IF NOT EXISTS "user_uuid_policies" (
  "user_uuid" UUID NOT NULL,
  "policy_uuid" UUID NOT NULL,
  PRIMARY KEY ("user_uuid", "policy_uuid"),
  FOREIGN KEY ("user_uuid") REFERENCES "user_uuids" ("user_uuid"),
  FOREIGN KEY ("policy_uuid") REFERENCES "policies" ("policy_uuid")
);

CREATE TABLE IF NOT EXISTS "group_name_policies" (
  "group_name" TEXT NOT NULL,
  "policy_uuid" UUID NOT NULL,
  PRIMARY KEY ("group_name", "policy_uuid"),
  FOREIGN KEY ("group_name") REFERENCES "group_names" ("group_name"),
  FOREIGN KEY ("policy_uuid") REFERENCES "policies" ("policy_uuid")
);

CREATE TABLE IF NOT EXISTS "group_uuid_policies" (
  "group_uuid" UUID NOT NULL,
  "policy_uuid" UUID NOT NULL,
  PRIMARY KEY ("group_uuid", "policy_uuid"),
  FOREIGN KEY ("group_uuid") REFERENCES "group_uuids" ("group_uuid"),
  FOREIGN KEY ("policy_uuid") REFERENCES "policies" ("policy_uuid")
);
