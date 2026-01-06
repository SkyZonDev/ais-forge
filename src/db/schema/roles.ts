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
import { authMethods } from './auth';
import { identities } from './identities';
import { organizations } from './organizations';

// ============================================================================
// PERMISSIONS (Système granulaire namespace:resource:action)
// ============================================================================

export const permissions = pgTable(
    'permissions',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        organizationId: uuid('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),

        // Clé composite: "users:profiles:read" ou "users:*:read" ou "*:*:*"
        key: varchar('key', { length: 255 }).notNull(),

        // Composants de la clé (dénormalisés pour les requêtes)
        namespace: varchar('namespace', { length: 63 }).notNull(),
        resource: varchar('resource', { length: 63 }).notNull(),
        action: varchar('action', { length: 63 }).notNull(),

        // Informations
        name: varchar('name', { length: 255 }).notNull(),
        description: text('description'),

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        updatedAt: timestamp('updated_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        deletedAt: timestamp('deleted_at', { withTimezone: true }),
    },
    (table) => [
        // Clé unique par organisation
        uniqueIndex('permission_org_key_unique_idx')
            .on(table.organizationId, table.key)
            .where(sql`${table.deletedAt} IS NULL`),

        // Recherche par composants (pour matching wildcard)
        index('permission_org_components_idx')
            .on(
                table.organizationId,
                table.namespace,
                table.resource,
                table.action
            )
            .where(sql`${table.deletedAt} IS NULL`),

        // Cleanup
        index('permission_deleted_at_idx')
            .on(table.deletedAt)
            .where(sql`${table.deletedAt} IS NOT NULL`),

        // Contrainte: key = namespace:resource:action
        check(
            'permission_key_format',
            sql`${table.key} = ${table.namespace} || ':' || ${table.resource} || ':' || ${table.action}`
        ),

        // Contrainte: caractères valides
        check(
            'permission_components_format',
            sql`${table.namespace} ~ '^[a-z0-9_*]+$' AND ${table.resource} ~ '^[a-z0-9_*]+$' AND ${table.action} ~ '^[a-z0-9_*]+$'`
        ),
    ]
);

// ============================================================================
// RÔLES (Groupes de permissions)
// ============================================================================

export const roles = pgTable(
    'roles',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        organizationId: uuid('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),

        // Identifiants
        slug: varchar('slug', { length: 63 }).notNull(),
        name: varchar('name', { length: 255 }).notNull(),
        description: text('description'),

        // Système
        isSystem: boolean('is_system').notNull().default(false),

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        updatedAt: timestamp('updated_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        deletedAt: timestamp('deleted_at', { withTimezone: true }),
    },
    (table) => [
        // Slug unique par organisation
        uniqueIndex('role_org_slug_unique_idx')
            .on(table.organizationId, table.slug)
            .where(sql`${table.deletedAt} IS NULL`),

        // Cleanup
        index('role_deleted_at_idx')
            .on(table.deletedAt)
            .where(sql`${table.deletedAt} IS NOT NULL`),

        // Contrainte: format slug
        check(
            'role_slug_format',
            sql`${table.slug} ~ '^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$'`
        ),
    ]
);

// ============================================================================
// ROLE_PERMISSIONS (Table de jonction)
// ============================================================================

export const rolePermissions = pgTable(
    'role_permissions',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        roleId: uuid('role_id')
            .notNull()
            .references(() => roles.id, { onDelete: 'cascade' }),
        permissionId: uuid('permission_id')
            .notNull()
            .references(() => permissions.id, { onDelete: 'cascade' }),
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
    },
    (table) => [
        // Contrainte d'unicité
        uniqueIndex('role_permission_unique_idx').on(
            table.roleId,
            table.permissionId
        ),

        // Index pour lookup inverse (permissions → rôles)
        index('role_permission_perm_idx').on(table.permissionId),
    ]
);

// ============================================================================
// IDENTITY_ROLES (Rôles assignés aux identités)
// ============================================================================

export const identityRoles = pgTable(
    'identity_roles',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        identityId: uuid('identity_id')
            .notNull()
            .references(() => identities.id, { onDelete: 'cascade' }),
        roleId: uuid('role_id')
            .notNull()
            .references(() => roles.id, { onDelete: 'cascade' }),

        // Traçabilité
        grantedBy: uuid('granted_by').references(() => identities.id, {
            onDelete: 'set null',
        }),

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        expiresAt: timestamp('expires_at', { withTimezone: true }), // Rôles temporaires
    },
    (table) => [
        // Contrainte d'unicité
        uniqueIndex('identity_role_unique_idx').on(
            table.identityId,
            table.roleId
        ),

        // Index pour lookup inverse
        index('identity_role_role_idx').on(table.roleId),

        // Index pour rôles temporaires (cleanup)
        index('identity_role_expires_idx')
            .on(table.expiresAt)
            .where(sql`${table.expiresAt} IS NOT NULL`),

        // Contrainte: expiration future
        check(
            'identity_role_expires_future',
            sql`${table.expiresAt} IS NULL OR ${table.expiresAt} > ${table.createdAt}`
        ),
    ]
);

// ============================================================================
// IDENTITY_PERMISSIONS (Permissions directes)
// ============================================================================

export const identityPermissions = pgTable(
    'identity_permissions',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        identityId: uuid('identity_id')
            .notNull()
            .references(() => identities.id, { onDelete: 'cascade' }),
        permissionId: uuid('permission_id')
            .notNull()
            .references(() => permissions.id, { onDelete: 'cascade' }),

        // Traçabilité
        grantedBy: uuid('granted_by').references(() => identities.id, {
            onDelete: 'set null',
        }),

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        expiresAt: timestamp('expires_at', { withTimezone: true }),
    },
    (table) => [
        // Contrainte d'unicité
        uniqueIndex('identity_permission_unique_idx').on(
            table.identityId,
            table.permissionId
        ),

        // Index pour lookup inverse
        index('identity_permission_perm_idx').on(table.permissionId),

        // Index pour permissions temporaires
        index('identity_permission_expires_idx')
            .on(table.expiresAt)
            .where(sql`${table.expiresAt} IS NOT NULL`),

        // Contrainte
        check(
            'identity_permission_expires_future',
            sql`${table.expiresAt} IS NULL OR ${table.expiresAt} > ${table.createdAt}`
        ),
    ]
);

// ============================================================================
// AUTH_METHOD_PERMISSIONS (Permissions pour PATs/API keys)
// ============================================================================

export const authMethodPermissions = pgTable(
    'auth_method_permissions',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        authMethodId: uuid('auth_method_id')
            .notNull()
            .references(() => authMethods.id, { onDelete: 'cascade' }),
        permissionId: uuid('permission_id')
            .notNull()
            .references(() => permissions.id, { onDelete: 'cascade' }),
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
    },
    (table) => [
        // Contrainte d'unicité
        uniqueIndex('auth_method_permission_unique_idx').on(
            table.authMethodId,
            table.permissionId
        ),

        // Index pour l'authMethod (listing des permissions)
        index('auth_method_permission_method_idx').on(table.authMethodId),
    ]
);
