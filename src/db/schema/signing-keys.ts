import { sql } from 'drizzle-orm';
import {
    boolean,
    check,
    index,
    pgTable,
    text,
    timestamp,
    uniqueIndex,
    uuid,
    varchar,
} from 'drizzle-orm/pg-core';
import { signingAlgorithmEnum } from './enum';

export const signingKeys = pgTable(
    'signing_keys',
    {
        id: uuid('id').primaryKey().defaultRandom(),

        // Identifiant unique de la clé
        kid: varchar('kid', { length: 64 }).notNull().unique(), // "2025-01-a3f9"

        // Algorithme (enum pour sécurité)
        algorithm: signingAlgorithmEnum('algorithm').notNull().default('ES256'),

        // Clés (private chiffrée avec master key)
        privateKeyEncrypted: text('private_key_encrypted').notNull(),
        publicKey: text('public_key').notNull(), // PEM pour JWKS

        // Statut
        isActive: boolean('is_active').notNull().default(true),

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        rotatedAt: timestamp('rotated_at', { withTimezone: true }), // NULL = clé active
        expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    },
    (table) => [
        // Lookup par kid (validation JWT)
        uniqueIndex('signing_key_kid_idx').on(table.kid),

        // Clé active la plus récente
        index('signing_key_active_recent_idx')
            .on(table.isActive, table.createdAt.desc())
            .where(sql`${table.isActive} = true`),

        // Cleanup des clés expirées
        index('signing_key_expires_idx').on(table.expiresAt),

        // Contrainte: expiration future à la création
        check(
            'signing_key_expires_future',
            sql`${table.expiresAt} > ${table.createdAt}`
        ),

        // Contrainte: kid format
        check('signing_key_kid_format', sql`${table.kid} ~ '^[a-zA-Z0-9_-]+$'`),
    ]
);
