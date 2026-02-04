import { sql } from 'drizzle-orm';
import {
    check,
    index,
    jsonb,
    pgTable,
    timestamp,
    uuid,
    varchar,
} from 'drizzle-orm/pg-core';

export const organizations = pgTable(
    'organizations',
    {
        id: uuid('id').primaryKey().defaultRandom(),

        // Identifiers
        slug: varchar('slug', { length: 63 }).notNull().unique(), // DNS-safe, max 63 chars
        name: varchar('name', { length: 255 }).notNull(),

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        updatedAt: timestamp('updated_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        deletedAt: timestamp('deleted_at', { withTimezone: true }),

        // Extensible metadata
        metadata: jsonb('metadata')
            .$type<Record<string, unknown>>()
            .default({})
            .notNull(),
    },
    (table) => [
        // Partial index for active orgs (excludes soft-deleted)
        index('org_active_slug_idx')
            .on(table.slug)
            .where(sql`${table.deletedAt} IS NULL`),

        // Index for soft-deleted cleanup
        index('org_deleted_at_idx')
            .on(table.deletedAt)
            .where(sql`${table.deletedAt} IS NOT NULL`),

        // Constraint: DNS-safe slug format
        check(
            'org_slug_format',
            sql`${table.slug} ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'`
        ),
    ]
);
