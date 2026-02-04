CREATE TYPE "public"."auth_method_type" AS ENUM('password', 'pat', 'api_key');--> statement-breakpoint
CREATE TYPE "public"."event_category" AS ENUM('auth', 'permission', 'admin', 'security', 'identity', 'token');--> statement-breakpoint
CREATE TYPE "public"."event_severity" AS ENUM('debug', 'info', 'warning', 'error', 'critical');--> statement-breakpoint
CREATE TYPE "public"."identity_status" AS ENUM('active', 'suspended', 'deleted');--> statement-breakpoint
CREATE TYPE "public"."identity_type" AS ENUM('human', 'service', 'machine');--> statement-breakpoint
CREATE TYPE "public"."revoked_reason" AS ENUM('used', 'stolen', 'manual', 'family_revoked', 'expired', 'logout');--> statement-breakpoint
CREATE TYPE "public"."signing_algorithm" AS ENUM('EdDSA', 'ES384', 'ES256', 'ML-DSA-65', 'ML-DSA-87', 'ML-DSA-44', 'SLH-DSA-SHA2-192f', 'RS256');--> statement-breakpoint
CREATE TABLE "audit_logs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"identity_id" uuid,
	"session_id" uuid,
	"auth_method_id" uuid,
	"event_type" varchar(127) NOT NULL,
	"event_category" "event_category" NOT NULL,
	"severity" "event_severity" NOT NULL,
	"ip_address" "inet",
	"user_agent" text,
	"resource_type" varchar(63),
	"resource_id" uuid,
	"success" boolean NOT NULL,
	"error_message" text,
	"error_code" varchar(63),
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "audit_log_event_type_format" CHECK ("audit_logs"."event_type" ~ '^[a-z]+\.[a-z]+\.[a-z]+$')
);
--> statement-breakpoint
CREATE TABLE "auth_methods" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"identity_id" uuid NOT NULL,
	"organization_id" uuid,
	"type" "auth_method_type" NOT NULL,
	"name" varchar(255),
	"credential_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	CONSTRAINT "auth_method_expires_future" CHECK ("auth_methods"."expires_at" IS NULL OR "auth_methods"."expires_at" > "auth_methods"."created_at")
);
--> statement-breakpoint
CREATE TABLE "refresh_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"identity_id" uuid NOT NULL,
	"organization_id" uuid NOT NULL,
	"session_id" uuid,
	"auth_method_id" uuid,
	"token_family_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"parent_token_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"used_at" timestamp with time zone,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoked_reason" "revoked_reason",
	CONSTRAINT "refresh_tokens_token_hash_unique" UNIQUE("token_hash"),
	CONSTRAINT "refresh_token_expires_future" CHECK ("refresh_tokens"."expires_at" > "refresh_tokens"."created_at"),
	CONSTRAINT "refresh_token_source_xor" CHECK (("refresh_tokens"."session_id" IS NULL) != ("refresh_tokens"."auth_method_id" IS NULL))
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"identity_id" uuid NOT NULL,
	"organization_id" uuid NOT NULL,
	"token_family_id" uuid NOT NULL,
	"session_token_hash" text NOT NULL,
	"ip_address" "inet" NOT NULL,
	"user_agent" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_activity_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	CONSTRAINT "sessions_session_token_hash_unique" UNIQUE("session_token_hash"),
	CONSTRAINT "session_expires_future" CHECK ("sessions"."expires_at" > "sessions"."created_at")
);
--> statement-breakpoint
CREATE TABLE "identities" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"type" "identity_type" NOT NULL,
	"status" "identity_status" DEFAULT 'active' NOT NULL,
	"display_name" varchar(255) NOT NULL,
	"email" varchar(320),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_activity_at" timestamp with time zone,
	"deleted_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	CONSTRAINT "identity_email_format" CHECK ("identities"."email" IS NULL OR "identities"."email" ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$')
);
--> statement-breakpoint
CREATE TABLE "organizations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" varchar(63) NOT NULL,
	"name" varchar(255) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	CONSTRAINT "organizations_slug_unique" UNIQUE("slug"),
	CONSTRAINT "org_slug_format" CHECK ("organizations"."slug" ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$')
);
--> statement-breakpoint
CREATE TABLE "rate_limits" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid,
	"identity_id" uuid,
	"key" varchar(255) NOT NULL,
	"window_start" timestamp with time zone NOT NULL,
	"window_duration" interval NOT NULL,
	"attempt_count" integer DEFAULT 0 NOT NULL,
	"last_attempt_at" timestamp with time zone NOT NULL,
	"blocked_until" timestamp with time zone,
	CONSTRAINT "rate_limit_count_positive" CHECK ("rate_limits"."attempt_count" >= 0)
);
--> statement-breakpoint
CREATE TABLE "auth_method_permissions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"auth_method_id" uuid NOT NULL,
	"permission_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "identity_permissions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"identity_id" uuid NOT NULL,
	"permission_id" uuid NOT NULL,
	"granted_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	CONSTRAINT "identity_permission_expires_future" CHECK ("identity_permissions"."expires_at" IS NULL OR "identity_permissions"."expires_at" > "identity_permissions"."created_at")
);
--> statement-breakpoint
CREATE TABLE "identity_roles" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"identity_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"granted_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	CONSTRAINT "identity_role_expires_future" CHECK ("identity_roles"."expires_at" IS NULL OR "identity_roles"."expires_at" > "identity_roles"."created_at")
);
--> statement-breakpoint
CREATE TABLE "permissions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"key" varchar(255) NOT NULL,
	"namespace" varchar(63) NOT NULL,
	"resource" varchar(63) NOT NULL,
	"action" varchar(63) NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "permission_key_format" CHECK ("permissions"."key" = "permissions"."namespace" || ':' || "permissions"."resource" || ':' || "permissions"."action"),
	CONSTRAINT "permission_components_format" CHECK ("permissions"."namespace" ~ '^[a-z0-9_*]+$' AND "permissions"."resource" ~ '^[a-z0-9_*]+$' AND "permissions"."action" ~ '^[a-z0-9_*]+$')
);
--> statement-breakpoint
CREATE TABLE "role_permissions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"role_id" uuid NOT NULL,
	"permission_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "roles" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"slug" varchar(63) NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"is_system" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "role_slug_format" CHECK ("roles"."slug" ~ '^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$')
);
--> statement-breakpoint
CREATE TABLE "signing_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"kid" varchar(64) NOT NULL,
	"algorithm" "signing_algorithm" DEFAULT 'ES256' NOT NULL,
	"private_key_encrypted" text NOT NULL,
	"public_key" text NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"rotated_at" timestamp with time zone,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "signing_keys_kid_unique" UNIQUE("kid"),
	CONSTRAINT "signing_key_expires_future" CHECK ("signing_keys"."expires_at" > "signing_keys"."created_at"),
	CONSTRAINT "signing_key_kid_format" CHECK ("signing_keys"."kid" ~ '^[a-zA-Z0-9_-]+$')
);
--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_identity_id_identities_id_fk" FOREIGN KEY ("identity_id") REFERENCES "public"."identities"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_auth_method_id_auth_methods_id_fk" FOREIGN KEY ("auth_method_id") REFERENCES "public"."auth_methods"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_methods" ADD CONSTRAINT "auth_methods_identity_id_identities_id_fk" FOREIGN KEY ("identity_id") REFERENCES "public"."identities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_methods" ADD CONSTRAINT "auth_methods_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_identity_id_identities_id_fk" FOREIGN KEY ("identity_id") REFERENCES "public"."identities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_auth_method_id_auth_methods_id_fk" FOREIGN KEY ("auth_method_id") REFERENCES "public"."auth_methods"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_parent_token_id_refresh_tokens_id_fk" FOREIGN KEY ("parent_token_id") REFERENCES "public"."refresh_tokens"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_identity_id_identities_id_fk" FOREIGN KEY ("identity_id") REFERENCES "public"."identities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identities" ADD CONSTRAINT "identities_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rate_limits" ADD CONSTRAINT "rate_limits_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rate_limits" ADD CONSTRAINT "rate_limits_identity_id_identities_id_fk" FOREIGN KEY ("identity_id") REFERENCES "public"."identities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_method_permissions" ADD CONSTRAINT "auth_method_permissions_auth_method_id_auth_methods_id_fk" FOREIGN KEY ("auth_method_id") REFERENCES "public"."auth_methods"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_method_permissions" ADD CONSTRAINT "auth_method_permissions_permission_id_permissions_id_fk" FOREIGN KEY ("permission_id") REFERENCES "public"."permissions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_permissions" ADD CONSTRAINT "identity_permissions_identity_id_identities_id_fk" FOREIGN KEY ("identity_id") REFERENCES "public"."identities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_permissions" ADD CONSTRAINT "identity_permissions_permission_id_permissions_id_fk" FOREIGN KEY ("permission_id") REFERENCES "public"."permissions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_permissions" ADD CONSTRAINT "identity_permissions_granted_by_identities_id_fk" FOREIGN KEY ("granted_by") REFERENCES "public"."identities"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_roles" ADD CONSTRAINT "identity_roles_identity_id_identities_id_fk" FOREIGN KEY ("identity_id") REFERENCES "public"."identities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_roles" ADD CONSTRAINT "identity_roles_role_id_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_roles" ADD CONSTRAINT "identity_roles_granted_by_identities_id_fk" FOREIGN KEY ("granted_by") REFERENCES "public"."identities"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "permissions" ADD CONSTRAINT "permissions_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_role_id_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_permission_id_permissions_id_fk" FOREIGN KEY ("permission_id") REFERENCES "public"."permissions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "roles" ADD CONSTRAINT "roles_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_log_org_created_idx" ON "audit_logs" USING btree ("organization_id","created_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "audit_log_identity_created_idx" ON "audit_logs" USING btree ("identity_id","created_at" DESC NULLS LAST) WHERE "audit_logs"."identity_id" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "audit_log_category_severity_idx" ON "audit_logs" USING btree ("organization_id","event_category","severity","created_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "audit_log_event_type_idx" ON "audit_logs" USING btree ("organization_id","event_type","created_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "audit_log_security_critical_idx" ON "audit_logs" USING btree ("organization_id","created_at" DESC NULLS LAST) WHERE "audit_logs"."event_category" = 'security' OR "audit_logs"."severity" = 'critical';--> statement-breakpoint
CREATE INDEX "audit_log_ip_idx" ON "audit_logs" USING btree ("ip_address","created_at" DESC NULLS LAST) WHERE "audit_logs"."ip_address" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "auth_method_identity_active_idx" ON "auth_methods" USING btree ("identity_id","type") WHERE "auth_methods"."revoked_at" IS NULL;--> statement-breakpoint
CREATE INDEX "auth_method_org_idx" ON "auth_methods" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "auth_method_revoked_idx" ON "auth_methods" USING btree ("revoked_at") WHERE "auth_methods"."revoked_at" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "auth_method_expires_idx" ON "auth_methods" USING btree ("expires_at") WHERE "auth_methods"."expires_at" IS NOT NULL AND "auth_methods"."revoked_at" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "refresh_token_hash_idx" ON "refresh_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "refresh_token_family_active_idx" ON "refresh_tokens" USING btree ("token_family_id") WHERE "refresh_tokens"."revoked_at" IS NULL;--> statement-breakpoint
CREATE INDEX "refresh_token_identity_valid_idx" ON "refresh_tokens" USING btree ("identity_id","expires_at") WHERE "refresh_tokens"."revoked_at" IS NULL;--> statement-breakpoint
CREATE INDEX "refresh_token_expires_idx" ON "refresh_tokens" USING btree ("expires_at") WHERE "refresh_tokens"."revoked_at" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "session_token_hash_idx" ON "sessions" USING btree ("session_token_hash");--> statement-breakpoint
CREATE INDEX "session_identity_active_idx" ON "sessions" USING btree ("identity_id") WHERE "sessions"."revoked_at" IS NULL;--> statement-breakpoint
CREATE INDEX "session_token_family_idx" ON "sessions" USING btree ("token_family_id");--> statement-breakpoint
CREATE INDEX "session_org_idx" ON "sessions" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "session_expires_idx" ON "sessions" USING btree ("expires_at") WHERE "sessions"."revoked_at" IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "identity_org_email_unique_idx" ON "identities" USING btree ("organization_id","email") WHERE "identities"."email" IS NOT NULL AND "identities"."deleted_at" IS NULL;--> statement-breakpoint
CREATE INDEX "identity_org_status_active_idx" ON "identities" USING btree ("organization_id","status") WHERE "identities"."deleted_at" IS NULL;--> statement-breakpoint
CREATE INDEX "identity_org_type_idx" ON "identities" USING btree ("organization_id","type") WHERE "identities"."deleted_at" IS NULL;--> statement-breakpoint
CREATE INDEX "identity_deleted_at_idx" ON "identities" USING btree ("deleted_at") WHERE "identities"."deleted_at" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "org_active_slug_idx" ON "organizations" USING btree ("slug") WHERE "organizations"."deleted_at" IS NULL;--> statement-breakpoint
CREATE INDEX "org_deleted_at_idx" ON "organizations" USING btree ("deleted_at") WHERE "organizations"."deleted_at" IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "rate_limit_key_window_unique_idx" ON "rate_limits" USING btree ("key","window_start");--> statement-breakpoint
CREATE INDEX "rate_limit_blocked_idx" ON "rate_limits" USING btree ("blocked_until") WHERE "rate_limits"."blocked_until" IS NOT NULL;--> statement-breakpoint
CREATE INDEX "rate_limit_window_start_idx" ON "rate_limits" USING btree ("window_start");--> statement-breakpoint
CREATE UNIQUE INDEX "auth_method_permission_unique_idx" ON "auth_method_permissions" USING btree ("auth_method_id","permission_id");--> statement-breakpoint
CREATE INDEX "auth_method_permission_method_idx" ON "auth_method_permissions" USING btree ("auth_method_id");--> statement-breakpoint
CREATE UNIQUE INDEX "identity_permission_unique_idx" ON "identity_permissions" USING btree ("identity_id","permission_id");--> statement-breakpoint
CREATE INDEX "identity_permission_perm_idx" ON "identity_permissions" USING btree ("permission_id");--> statement-breakpoint
CREATE INDEX "identity_permission_expires_idx" ON "identity_permissions" USING btree ("expires_at") WHERE "identity_permissions"."expires_at" IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "identity_role_unique_idx" ON "identity_roles" USING btree ("identity_id","role_id");--> statement-breakpoint
CREATE INDEX "identity_role_role_idx" ON "identity_roles" USING btree ("role_id");--> statement-breakpoint
CREATE INDEX "identity_role_expires_idx" ON "identity_roles" USING btree ("expires_at") WHERE "identity_roles"."expires_at" IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "permission_org_key_unique_idx" ON "permissions" USING btree ("organization_id","key") WHERE "permissions"."deleted_at" IS NULL;--> statement-breakpoint
CREATE INDEX "permission_org_components_idx" ON "permissions" USING btree ("organization_id","namespace","resource","action") WHERE "permissions"."deleted_at" IS NULL;--> statement-breakpoint
CREATE INDEX "permission_deleted_at_idx" ON "permissions" USING btree ("deleted_at") WHERE "permissions"."deleted_at" IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "role_permission_unique_idx" ON "role_permissions" USING btree ("role_id","permission_id");--> statement-breakpoint
CREATE INDEX "role_permission_perm_idx" ON "role_permissions" USING btree ("permission_id");--> statement-breakpoint
CREATE UNIQUE INDEX "role_org_slug_unique_idx" ON "roles" USING btree ("organization_id","slug") WHERE "roles"."deleted_at" IS NULL;--> statement-breakpoint
CREATE INDEX "role_deleted_at_idx" ON "roles" USING btree ("deleted_at") WHERE "roles"."deleted_at" IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "signing_key_kid_idx" ON "signing_keys" USING btree ("kid");--> statement-breakpoint
CREATE INDEX "signing_key_active_recent_idx" ON "signing_keys" USING btree ("is_active","created_at" DESC NULLS LAST) WHERE "signing_keys"."is_active" = true;--> statement-breakpoint
CREATE INDEX "signing_key_expires_idx" ON "signing_keys" USING btree ("expires_at");

--> Add automatic update TRIGGER
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER identities_updated_at
    BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER permissions_updated_at
    BEFORE UPDATE ON permissions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
