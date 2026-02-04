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

        // Unique key identifier
        kid: varchar('kid', { length: 64 }).notNull().unique(), // "2025-01-a3f9"

        // Signing algorithm (enum for security)
        algorithm: signingAlgorithmEnum('algorithm').notNull().default('ES256'),

        // Keys (private key encrypted with master key)
        privateKeyEncrypted: text('private_key_encrypted').notNull(),
        publicKey: text('public_key').notNull(), // PEM format for JWKS

        // Status
        isActive: boolean('is_active').notNull().default(true),

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        rotatedAt: timestamp('rotated_at', { withTimezone: true }), // NULL = active key
        expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    },
    (table) => [
        // Lookup by kid (JWT validation)
        uniqueIndex('signing_key_kid_idx').on(table.kid),

        // Most recent active key
        index('signing_key_active_recent_idx')
            .on(table.isActive, table.createdAt.desc())
            .where(sql`${table.isActive} = true`),

        // Cleanup expired keys
        index('signing_key_expires_idx').on(table.expiresAt),

        // Constraint: expiration must be in the future at creation
        check(
            'signing_key_expires_future',
            sql`${table.expiresAt} > ${table.createdAt}`
        ),

        // Constraint: kid format validation
        check('signing_key_kid_format', sql`${table.kid} ~ '^[a-zA-Z0-9_-]+$'`),
    ]
);
