import { sql } from 'drizzle-orm';
import {
    boolean,
    check,
    index,
    jsonb,
    pgTable,
    timestamp,
    uniqueIndex,
    uuid,
    varchar,
} from 'drizzle-orm/pg-core';
import { identityStatusEnum, identityTypeEnum } from './enum';
import { organizations } from './organizations';

export const identities = pgTable(
    'identities',
    {
        id: uuid('id').primaryKey().defaultRandom(),

        // Type and status
        type: identityTypeEnum('type').notNull(),
        status: identityStatusEnum('status').notNull().default('active'),

        // Information
        displayName: varchar('display_name', { length: 255 }).notNull(),
        email: varchar('email', { length: 320 }), // RFC 5321 max length

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        updatedAt: timestamp('updated_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        lastActivityAt: timestamp('last_activity_at', { withTimezone: true }),
        deletedAt: timestamp('deleted_at', { withTimezone: true }),

        // Extensible metadata
        metadata: jsonb('metadata')
            .$type<Record<string, unknown>>()
            .default({})
            .notNull(),
    },
    (table) => [
        // Unique email per org (only for non-null values)
        uniqueIndex('identity_org_email_unique_idx')
            .on(table.email)
            .where(
                sql`${table.email} IS NOT NULL AND ${table.deletedAt} IS NULL`
            ),

        // Lookup active identities by org and status
        index('identity_org_status_active_idx')
            .on(table.status)
            .where(sql`${table.deletedAt} IS NULL`),

        // Index for identity type (filtering human vs machine)
        index('identity_org_type_idx')
            .on(table.type)
            .where(sql`${table.deletedAt} IS NULL`),

        // Cleanup soft-deleted
        index('identity_deleted_at_idx')
            .on(table.deletedAt)
            .where(sql`${table.deletedAt} IS NOT NULL`),

        // Constraint: basic email format
        check(
            'identity_email_format',
            sql`${table.email} IS NULL OR ${table.email} ~* '^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$'`
        ),
    ]
);

export const identityOrganizations = pgTable(
    'identity_organizations',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        identityId: uuid('identity_id')
            .notNull()
            .references(() => identities.id, { onDelete: 'cascade' }),
        organizationId: uuid('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),

        // Primary organization (for default context)
        isPrimary: boolean('is_primary').notNull().default(false),

        // Display name override for this org (optional)
        // Ex: "John Smith" globally, but "JS" in org A
        displayNameOverride: varchar('display_name_override', { length: 255 }),

        // Invitation/join tracking
        invitedBy: uuid('invited_by').references(() => identities.id, {
            onDelete: 'set null',
        }),
        invitedAt: timestamp('invited_at', { withTimezone: true }),
        joinedAt: timestamp('joined_at', { withTimezone: true })
            .notNull()
            .defaultNow(),

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        updatedAt: timestamp('updated_at', { withTimezone: true })
            .notNull()
            .defaultNow(),

        // Soft delete (user leaves org or is removed)
        leftAt: timestamp('left_at', { withTimezone: true }),

        // Extensible metadata (org-specific settings)
        metadata: jsonb('metadata')
            .$type<Record<string, unknown>>()
            .default({})
            .notNull(),
    },
    (table) => [
        // Unique (identity, organization) pair
        uniqueIndex('identity_org_unique_idx')
            .on(table.identityId, table.organizationId)
            .where(sql`${table.leftAt} IS NULL`),

        // Only ONE primary organization per identity
        uniqueIndex('identity_primary_org_unique_idx')
            .on(table.identityId)
            .where(sql`${table.isPrimary} = true AND ${table.leftAt} IS NULL`),

        // Lookup members of an organization
        index('identity_org_org_idx')
            .on(table.organizationId)
            .where(sql`${table.leftAt} IS NULL`),

        // Lookup organizations for an identity
        index('identity_org_identity_idx')
            .on(table.identityId)
            .where(sql`${table.leftAt} IS NULL`),

        // Index for cleanup (left members)
        index('identity_org_left_at_idx')
            .on(table.leftAt)
            .where(sql`${table.leftAt} IS NOT NULL`),

        // Constraint: joinedAt <= leftAt (if left)
        check(
            'identity_org_left_after_joined',
            sql`${table.leftAt} IS NULL OR ${table.leftAt} >= ${table.joinedAt}`
        ),
    ]
);
