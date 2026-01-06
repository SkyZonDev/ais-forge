import { sql } from 'drizzle-orm';
import {
    type AnyPgColumn,
    check,
    index,
    inet,
    jsonb,
    pgTable,
    text,
    timestamp,
    uniqueIndex,
    uuid,
    varchar,
} from 'drizzle-orm/pg-core';
import { authMethodTypeEnum, revokedReasonEnum } from './enum';
import { identities } from './identities';
import { organizations } from './organizations';

export const authMethods = pgTable(
    'auth_methods',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        identityId: uuid('identity_id')
            .notNull()
            .references(() => identities.id, { onDelete: 'cascade' }),
        organizationId: uuid('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),

        // Type and identification
        type: authMethodTypeEnum('type').notNull(),
        name: varchar('name', { length: 255 }), // "CI Pipeline PAT", "Mobile App Key"

        // Credentials (never stored in plain text)
        credentialHash: text('credential_hash').notNull(), // argon2id for passwords, SHA-256 for tokens

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
        expiresAt: timestamp('expires_at', { withTimezone: true }),
        revokedAt: timestamp('revoked_at', { withTimezone: true }),

        // Extensible metadata (scopes, IP whitelist, etc.)
        metadata: jsonb('metadata')
            .$type<Record<string, unknown>>()
            .default({})
            .notNull(),
    },
    (table) => [
        // Lookup active methods by identity
        index('auth_method_identity_active_idx')
            .on(table.identityId, table.type)
            .where(sql`${table.revokedAt} IS NULL`),

        // Index by organization for admin
        index('auth_method_org_idx').on(table.organizationId),

        // Cleanup revoked methods
        index('auth_method_revoked_idx')
            .on(table.revokedAt)
            .where(sql`${table.revokedAt} IS NOT NULL`),

        // Index for expiration (automatic cleanup)
        index('auth_method_expires_idx')
            .on(table.expiresAt)
            .where(
                sql`${table.expiresAt} IS NOT NULL AND ${table.revokedAt} IS NULL`
            ),

        // Constraint: expiration must be in the future at creation
        check(
            'auth_method_expires_future',
            sql`${table.expiresAt} IS NULL OR ${table.expiresAt} > ${table.createdAt}`
        ),
    ]
);

export const sessions = pgTable(
    'sessions',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        identityId: uuid('identity_id')
            .notNull()
            .references(() => identities.id, { onDelete: 'cascade' }),
        organizationId: uuid('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),

        // Theft detection
        tokenFamilyId: uuid('token_family_id').notNull(),

        // Session token (hashed)
        sessionTokenHash: text('session_token_hash').notNull().unique(),

        // Client information
        ipAddress: inet('ip_address').notNull(),
        userAgent: text('user_agent'),

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        lastActivityAt: timestamp('last_activity_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
        revokedAt: timestamp('revoked_at', { withTimezone: true }),

        // Metadata (device info, geolocation)
        metadata: jsonb('metadata')
            .$type<Record<string, unknown>>()
            .default({})
            .notNull(),
    },
    (table) => [
        // Lookup by token hash (authentication)
        uniqueIndex('session_token_hash_idx').on(table.sessionTokenHash),

        // Active sessions by identity
        index('session_identity_active_idx')
            .on(table.identityId)
            .where(
                sql`${table.revokedAt} IS NULL AND ${table.expiresAt} > NOW()`
            ),

        // Theft detection by family
        index('session_token_family_idx').on(table.tokenFamilyId),

        // Index for organization (admin)
        index('session_org_idx').on(table.organizationId),

        // Cleanup expired sessions
        index('session_expires_idx')
            .on(table.expiresAt)
            .where(sql`${table.revokedAt} IS NULL`),

        // Constraint: expiration must be in the future
        check(
            'session_expires_future',
            sql`${table.expiresAt} > ${table.createdAt}`
        ),
    ]
);

export const refreshTokens = pgTable(
    'refresh_tokens',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        identityId: uuid('identity_id')
            .notNull()
            .references(() => identities.id, { onDelete: 'cascade' }),
        organizationId: uuid('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),

        // Optional links (session OR authMethod)
        sessionId: uuid('session_id').references(() => sessions.id, {
            onDelete: 'cascade',
        }),
        authMethodId: uuid('auth_method_id').references(() => authMethods.id, {
            onDelete: 'cascade',
        }),

        // CRITICAL: Theft detection
        tokenFamilyId: uuid('token_family_id').notNull(),
        tokenHash: text('token_hash').notNull().unique(),
        parentTokenId: uuid('parent_token_id').references(
            (): AnyPgColumn => refreshTokens.id,
            { onDelete: 'set null' }
        ),

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        usedAt: timestamp('used_at', { withTimezone: true }),
        expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
        revokedAt: timestamp('revoked_at', { withTimezone: true }),

        // Revocation reason (enum for consistency)
        revokedReason: revokedReasonEnum('revoked_reason'),
    },
    (table) => [
        // Lookup by hash (authentication)
        uniqueIndex('refresh_token_hash_idx').on(table.tokenHash),

        // Theft detection: active tokens by family
        index('refresh_token_family_active_idx')
            .on(table.tokenFamilyId)
            .where(sql`${table.revokedAt} IS NULL`),

        // Valid tokens by identity (for listing)
        index('refresh_token_identity_valid_idx')
            .on(table.identityId, table.expiresAt)
            .where(
                sql`${table.revokedAt} IS NULL AND ${table.expiresAt} > NOW()`
            ),

        // Cleanup expired tokens
        index('refresh_token_expires_idx')
            .on(table.expiresAt)
            .where(sql`${table.revokedAt} IS NULL`),

        // Constraint: expiration must be in the future
        check(
            'refresh_token_expires_future',
            sql`${table.expiresAt} > ${table.createdAt}`
        ),

        // Constraint: session XOR authMethod (not both)
        check(
            'refresh_token_source_xor',
            sql`(${table.sessionId} IS NULL) != (${table.authMethodId} IS NULL)`
        ),
    ]
);
