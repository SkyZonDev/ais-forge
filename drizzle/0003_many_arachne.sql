ALTER TYPE "public"."signing_algorithm" ADD VALUE 'ES512' BEFORE 'RS256';--> statement-breakpoint
CREATE TABLE "identity_organizations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"identity_id" uuid NOT NULL,
	"organization_id" uuid NOT NULL,
	"is_primary" boolean DEFAULT false NOT NULL,
	"display_name_override" varchar(255),
	"invited_by" uuid,
	"invited_at" timestamp with time zone,
	"joined_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"left_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	CONSTRAINT "identity_org_left_after_joined" CHECK ("identity_organizations"."left_at" IS NULL OR "identity_organizations"."left_at" >= "identity_organizations"."joined_at")
);
--> statement-breakpoint
ALTER TABLE "auth_methods" DROP CONSTRAINT "auth_method_expires_future";--> statement-breakpoint
ALTER TABLE "identity_permissions" DROP CONSTRAINT "identity_permission_expires_future";--> statement-breakpoint
ALTER TABLE "identity_roles" DROP CONSTRAINT "identity_role_expires_future";--> statement-breakpoint
ALTER TABLE "identities" DROP CONSTRAINT "identities_organization_id_organizations_id_fk";
--> statement-breakpoint
DROP INDEX "auth_method_identity_active_idx";--> statement-breakpoint
DROP INDEX "auth_method_org_idx";--> statement-breakpoint
DROP INDEX "auth_method_revoked_idx";--> statement-breakpoint
DROP INDEX "auth_method_expires_idx";--> statement-breakpoint
DROP INDEX "refresh_token_family_active_idx";--> statement-breakpoint
DROP INDEX "refresh_token_identity_valid_idx";--> statement-breakpoint
DROP INDEX "refresh_token_expires_idx";--> statement-breakpoint
DROP INDEX "session_identity_active_idx";--> statement-breakpoint
DROP INDEX "session_expires_idx";--> statement-breakpoint
DROP INDEX "identity_org_email_unique_idx";--> statement-breakpoint
DROP INDEX "identity_org_status_active_idx";--> statement-breakpoint
DROP INDEX "identity_org_type_idx";--> statement-breakpoint
DROP INDEX "identity_permission_unique_idx";--> statement-breakpoint
DROP INDEX "identity_permission_expires_idx";--> statement-breakpoint
DROP INDEX "identity_role_unique_idx";--> statement-breakpoint
DROP INDEX "identity_role_expires_idx";--> statement-breakpoint
DROP INDEX "permission_org_key_unique_idx";--> statement-breakpoint
DROP INDEX "permission_org_components_idx";--> statement-breakpoint
DROP INDEX "permission_deleted_at_idx";--> statement-breakpoint
DROP INDEX "role_org_slug_unique_idx";--> statement-breakpoint
DROP INDEX "role_deleted_at_idx";--> statement-breakpoint
ALTER TABLE "identity_permissions" ADD COLUMN "organization_id" uuid NOT NULL;--> statement-breakpoint
ALTER TABLE "identity_roles" ADD COLUMN "organization_id" uuid NOT NULL;--> statement-breakpoint
ALTER TABLE "identity_organizations" ADD CONSTRAINT "identity_organizations_identity_id_identities_id_fk" FOREIGN KEY ("identity_id") REFERENCES "public"."identities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_organizations" ADD CONSTRAINT "identity_organizations_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_organizations" ADD CONSTRAINT "identity_organizations_invited_by_identities_id_fk" FOREIGN KEY ("invited_by") REFERENCES "public"."identities"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "identity_org_unique_idx" ON "identity_organizations" USING btree ("identity_id","organization_id") WHERE "identity_organizations"."left_at" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "identity_primary_org_unique_idx" ON "identity_organizations" USING btree ("identity_id") WHERE "identity_organizations"."is_primary" = true AND "identity_organizations"."left_at" IS NULL;--> statement-breakpoint
CREATE INDEX "identity_org_org_idx" ON "identity_organizations" USING btree ("organization_id") WHERE "identity_organizations"."left_at" IS NULL;--> statement-breakpoint
CREATE INDEX "identity_org_identity_idx" ON "identity_organizations" USING btree ("identity_id") WHERE "identity_organizations"."left_at" IS NULL;--> statement-breakpoint
CREATE INDEX "identity_org_left_at_idx" ON "identity_organizations" USING btree ("left_at") WHERE "identity_organizations"."left_at" IS NOT NULL;--> statement-breakpoint
ALTER TABLE "identity_permissions" ADD CONSTRAINT "identity_permissions_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_roles" ADD CONSTRAINT "identity_roles_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "refresh_token_identity_org_valid_idx" ON "refresh_tokens" USING btree ("identity_id","organization_id") WHERE "refresh_tokens"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "session_identity_org_active_idx" ON "sessions" USING btree ("identity_id","organization_id") WHERE "sessions"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "auth_method_permission_perm_idx" ON "auth_method_permissions" USING btree ("permission_id");--> statement-breakpoint
CREATE INDEX "identity_permission_identity_org_idx" ON "identity_permissions" USING btree ("identity_id","organization_id");--> statement-breakpoint
CREATE INDEX "identity_permission_org_idx" ON "identity_permissions" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "identity_role_identity_org_idx" ON "identity_roles" USING btree ("identity_id","organization_id");--> statement-breakpoint
CREATE INDEX "identity_role_org_idx" ON "identity_roles" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "auth_method_identity_active_idx" ON "auth_methods" USING btree ("identity_id","type") WHERE "auth_methods"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "auth_method_org_idx" ON "auth_methods" USING btree ("organization_id") WHERE "auth_methods"."organization_id" is not null;--> statement-breakpoint
CREATE INDEX "auth_method_revoked_idx" ON "auth_methods" USING btree ("revoked_at") WHERE "auth_methods"."revoked_at" is not null;--> statement-breakpoint
CREATE INDEX "auth_method_expires_idx" ON "auth_methods" USING btree ("expires_at") WHERE ("auth_methods"."expires_at" is not null and "auth_methods"."revoked_at" is null);--> statement-breakpoint
CREATE INDEX "refresh_token_family_active_idx" ON "refresh_tokens" USING btree ("token_family_id") WHERE "refresh_tokens"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "refresh_token_identity_valid_idx" ON "refresh_tokens" USING btree ("identity_id","expires_at") WHERE "refresh_tokens"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "refresh_token_expires_idx" ON "refresh_tokens" USING btree ("expires_at") WHERE "refresh_tokens"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "session_identity_active_idx" ON "sessions" USING btree ("identity_id") WHERE "sessions"."revoked_at" is null;--> statement-breakpoint
CREATE INDEX "session_expires_idx" ON "sessions" USING btree ("expires_at") WHERE "sessions"."revoked_at" is null;--> statement-breakpoint
CREATE UNIQUE INDEX "identity_org_email_unique_idx" ON "identities" USING btree ("email") WHERE "identities"."email" IS NOT NULL AND "identities"."deleted_at" IS NULL;--> statement-breakpoint
CREATE INDEX "identity_org_status_active_idx" ON "identities" USING btree ("status") WHERE "identities"."deleted_at" IS NULL;--> statement-breakpoint
CREATE INDEX "identity_org_type_idx" ON "identities" USING btree ("type") WHERE "identities"."deleted_at" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "identity_permission_unique_idx" ON "identity_permissions" USING btree ("identity_id","organization_id","permission_id");--> statement-breakpoint
CREATE INDEX "identity_permission_expires_idx" ON "identity_permissions" USING btree ("expires_at") WHERE "identity_permissions"."expires_at" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "identity_role_unique_idx" ON "identity_roles" USING btree ("identity_id","organization_id","role_id");--> statement-breakpoint
CREATE INDEX "identity_role_expires_idx" ON "identity_roles" USING btree ("expires_at") WHERE "identity_roles"."expires_at" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "permission_org_key_unique_idx" ON "permissions" USING btree ("organization_id","key") WHERE "permissions"."deleted_at" is null;--> statement-breakpoint
CREATE INDEX "permission_org_components_idx" ON "permissions" USING btree ("organization_id","namespace","resource","action") WHERE "permissions"."deleted_at" is null;--> statement-breakpoint
CREATE INDEX "permission_deleted_at_idx" ON "permissions" USING btree ("deleted_at") WHERE "permissions"."deleted_at" is not null;--> statement-breakpoint
CREATE UNIQUE INDEX "role_org_slug_unique_idx" ON "roles" USING btree ("organization_id","slug") WHERE "roles"."deleted_at" is null;--> statement-breakpoint
CREATE INDEX "role_deleted_at_idx" ON "roles" USING btree ("deleted_at") WHERE "roles"."deleted_at" is not null;--> statement-breakpoint
ALTER TABLE "identities" DROP COLUMN "organization_id";--> statement-breakpoint
ALTER TABLE "auth_methods" ADD CONSTRAINT "auth_method_password_no_org" CHECK (("auth_methods"."type" != 'password' or "auth_methods"."organization_id" is null));--> statement-breakpoint
ALTER TABLE "auth_methods" ADD CONSTRAINT "auth_method_expires_future" CHECK (("auth_methods"."expires_at" is null or "auth_methods"."expires_at" > "auth_methods"."created_at"));--> statement-breakpoint
ALTER TABLE "identity_permissions" ADD CONSTRAINT "identity_permission_expires_future" CHECK (("identity_permissions"."expires_at" is null or "identity_permissions"."expires_at" > "identity_permissions"."created_at"));--> statement-breakpoint
ALTER TABLE "identity_roles" ADD CONSTRAINT "identity_role_expires_future" CHECK (("identity_roles"."expires_at" is null or "identity_roles"."expires_at" > "identity_roles"."created_at"));