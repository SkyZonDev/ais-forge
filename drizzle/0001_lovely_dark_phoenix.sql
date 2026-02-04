ALTER TABLE "audit_logs" DROP CONSTRAINT "audit_logs_organization_id_organizations_id_fk";
--> statement-breakpoint
DROP INDEX "rate_limit_blocked_idx";--> statement-breakpoint
ALTER TABLE "audit_logs" ALTER COLUMN "organization_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "rate_limit_blocked_idx" ON "rate_limits" USING btree ("blocked_until") WHERE "rate_limits"."blocked_until" is not null;