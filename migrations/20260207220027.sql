-- Create "encryption_keys" table
CREATE TABLE "public"."encryption_keys" (
  "id" text NOT NULL,
  "enc_key_material" bytea NOT NULL,
  "state" text NOT NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  CONSTRAINT "uni_encryption_keys_id" PRIMARY KEY ("id")
);
-- Create "system_audit_events" table
CREATE TABLE "public"."system_audit_events" (
  "id" text NOT NULL,
  "type" text NOT NULL,
  "metadata" jsonb NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  CONSTRAINT "uni_system_audit_events_id" PRIMARY KEY ("id")
);
-- Create "system_params" table
CREATE TABLE "public"."system_params" (
  "id" text NOT NULL,
  "state" text NOT NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  CONSTRAINT "uni_system_params_id" PRIMARY KEY ("id")
);
-- Create "records" table
CREATE TABLE "public"."records" (
  "id" text NOT NULL,
  "name" text NOT NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  CONSTRAINT "uni_records_id" PRIMARY KEY ("id"),
  CONSTRAINT "uni_records_name" UNIQUE ("name")
);
-- Create "record_versions" table
CREATE TABLE "public"."record_versions" (
  "id" text NOT NULL,
  "record_id" text NOT NULL,
  "enc_key_id" text NOT NULL,
  "enc_value" bytea NOT NULL,
  "enc_nonce" bytea NOT NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  CONSTRAINT "uni_record_versions_id" PRIMARY KEY ("id"),
  CONSTRAINT "fk_record_versions_enc_key" FOREIGN KEY ("enc_key_id") REFERENCES "public"."encryption_keys" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "fk_record_versions_record" FOREIGN KEY ("record_id") REFERENCES "public"."records" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
