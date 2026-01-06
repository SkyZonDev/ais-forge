import { relations, sql } from 'drizzle-orm';
import {
    type AnyPgColumn,
    boolean,
    check,
    index,
    inet,
    integer,
    interval,
    jsonb,
    pgTable,
    text,
    timestamp,
    uniqueIndex,
    uuid,
    varchar,
} from 'drizzle-orm/pg-core';
import {
    authMethodTypeEnum,
    eventCategoryEnum,
    eventSeverityEnum,
    identityStatusEnum,
    identityTypeEnum,
    revokedReasonEnum,
    signingAlgorithmEnum,
} from './enum';
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

        // Type et identification
        type: authMethodTypeEnum('type').notNull(),
        name: varchar('name', { length: 255 }), // "CI Pipeline PAT", "Mobile App Key"

        // Credentials (jamais en clair)
        credentialHash: text('credential_hash').notNull(), // argon2id pour passwords, SHA-256 pour tokens

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
        expiresAt: timestamp('expires_at', { withTimezone: true }),
        revokedAt: timestamp('revoked_at', { withTimezone: true }),

        // Metadata extensible (scopes, IP whitelist, etc.)
        metadata: jsonb('metadata')
            .$type<Record<string, unknown>>()
            .default({})
            .notNull(),
    },
    (table) => [
        // Recherche des méthodes actives par identité
        index('auth_method_identity_active_idx')
            .on(table.identityId, table.type)
            .where(sql`${table.revokedAt} IS NULL`),

        // Index par organisation pour admin
        index('auth_method_org_idx').on(table.organizationId),

        // Cleanup des méthodes révoquées
        index('auth_method_revoked_idx')
            .on(table.revokedAt)
            .where(sql`${table.revokedAt} IS NOT NULL`),

        // Index pour expiration (cleanup automatique)
        index('auth_method_expires_idx')
            .on(table.expiresAt)
            .where(
                sql`${table.expiresAt} IS NOT NULL AND ${table.revokedAt} IS NULL`
            ),

        // Contrainte: expiration future à la création
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

        // Token de session (hashé)
        sessionTokenHash: text('session_token_hash').notNull().unique(),

        // Informations client
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
        // Lookup par token hash (authentification)
        uniqueIndex('session_token_hash_idx').on(table.sessionTokenHash),

        // Sessions actives par identité
        index('session_identity_active_idx')
            .on(table.identityId)
            .where(
                sql`${table.revokedAt} IS NULL AND ${table.expiresAt} > NOW()`
            ),

        // Theft detection par famille
        index('session_token_family_idx').on(table.tokenFamilyId),

        // Index pour l'organisation (admin)
        index('session_org_idx').on(table.organizationId),

        // Cleanup des sessions expirées
        index('session_expires_idx')
            .on(table.expiresAt)
            .where(sql`${table.revokedAt} IS NULL`),

        // Contrainte: expiration future
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

        // Liens optionnels (session OU authMethod)
        sessionId: uuid('session_id').references(() => sessions.id, {
            onDelete: 'cascade',
        }),
        authMethodId: uuid('auth_method_id').references(() => authMethods.id, {
            onDelete: 'cascade',
        }),

        // CRITIQUE: Theft detection
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

        // Raison de révocation (enum pour cohérence)
        revokedReason: revokedReasonEnum('revoked_reason'),
    },
    (table) => [
        // Lookup par hash (authentification)
        uniqueIndex('refresh_token_hash_idx').on(table.tokenHash),

        // Theft detection: tokens actifs par famille
        index('refresh_token_family_active_idx')
            .on(table.tokenFamilyId)
            .where(sql`${table.revokedAt} IS NULL`),

        // Tokens valides par identité (pour listing)
        index('refresh_token_identity_valid_idx')
            .on(table.identityId, table.expiresAt)
            .where(
                sql`${table.revokedAt} IS NULL AND ${table.expiresAt} > NOW()`
            ),

        // Cleanup des tokens expirés
        index('refresh_token_expires_idx')
            .on(table.expiresAt)
            .where(sql`${table.revokedAt} IS NULL`),

        // Contrainte: expiration future
        check(
            'refresh_token_expires_future',
            sql`${table.expiresAt} > ${table.createdAt}`
        ),

        // Contrainte: session XOR authMethod (pas les deux)
        check(
            'refresh_token_source_xor',
            sql`(${table.sessionId} IS NULL) != (${table.authMethodId} IS NULL)`
        ),
    ]
);
