ALTER TABLE "signing_keys" ALTER COLUMN "algorithm" SET DATA TYPE text;--> statement-breakpoint
ALTER TABLE "signing_keys" ALTER COLUMN "algorithm" SET DEFAULT 'ES256'::text;--> statement-breakpoint
DROP TYPE "public"."signing_algorithm";--> statement-breakpoint
CREATE TYPE "public"."signing_algorithm" AS ENUM('EdDSA', 'ES384', 'ES256', 'RS256');--> statement-breakpoint
ALTER TABLE "signing_keys" ALTER COLUMN "algorithm" SET DEFAULT 'ES256'::"public"."signing_algorithm";--> statement-breakpoint
ALTER TABLE "signing_keys" ALTER COLUMN "algorithm" SET DATA TYPE "public"."signing_algorithm" USING "algorithm"::"public"."signing_algorithm";