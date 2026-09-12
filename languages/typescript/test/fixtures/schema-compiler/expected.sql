-- Generated desired-state SQL from ores.schema-ir.v1; NOT a migration plan.

-- Apply only to a disposable desired-state database; use DPM diff/verify and reviewed migrator jobs for real targets.

CREATE SCHEMA "schema_demo";

CREATE TABLE "schema_demo"."members" (
  "display_name" pg_catalog.text CHECK (pg_catalog.char_length("display_name") <= 120),
  "enabled" pg_catalog.bool NOT NULL,
  "id" pg_catalog.uuid NOT NULL,
  "organization_id" pg_catalog.uuid NOT NULL,
  "rank" pg_catalog.int4 NOT NULL,
  CONSTRAINT "ores_ir_pk_d6d19721801d4654" PRIMARY KEY ("id")
);

CREATE TABLE "schema_demo"."organizations" (
  "id" pg_catalog.uuid NOT NULL,
  "name" pg_catalog.text NOT NULL CHECK (pg_catalog.char_length("name") >= 1) CHECK (pg_catalog.char_length("name") <= 100),
  CONSTRAINT "ores_ir_pk_999d739a75ca10ff" PRIMARY KEY ("id"),
  CONSTRAINT "ores_ir_uk_62ded27516956f3e" UNIQUE ("name")
);

ALTER TABLE "schema_demo"."members" ADD CONSTRAINT "ores_ir_fk_1065fc137e44992f" FOREIGN KEY ("organization_id") REFERENCES "schema_demo"."organizations" ("id") MATCH SIMPLE ON DELETE RESTRICT ON UPDATE NO ACTION;
