import { sql } from 'drizzle-orm';
import {
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
        organizationId: uuid('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),

        // Type et statut
        type: identityTypeEnum('type').notNull(),
        status: identityStatusEnum('status').notNull().default('active'),

        // Informations
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

        // Metadata extensible
        metadata: jsonb('metadata')
            .$type<Record<string, unknown>>()
            .default({})
            .notNull(),
    },
    (table) => [
        // Email unique par org (uniquement pour les valeurs non-null)
        uniqueIndex('identity_org_email_unique_idx')
            .on(table.organizationId, table.email)
            .where(
                sql`${table.email} IS NOT NULL AND ${table.deletedAt} IS NULL`
            ),

        // Recherche d'identités actives par org et statut
        index('identity_org_status_active_idx')
            .on(table.organizationId, table.status)
            .where(sql`${table.deletedAt} IS NULL`),

        // Index pour le type d'identité (filtrage human vs machine)
        index('identity_org_type_idx')
            .on(table.organizationId, table.type)
            .where(sql`${table.deletedAt} IS NULL`),

        // Cleanup des soft-deleted
        index('identity_deleted_at_idx')
            .on(table.deletedAt)
            .where(sql`${table.deletedAt} IS NOT NULL`),

        // Contrainte: format email basique
        check(
            'identity_email_format',
            sql`${table.email} IS NULL OR ${table.email} ~* '^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$'`
        ),
    ]
);
