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
// PERMISSIONS (Granular system namespace:resource:action)
// ============================================================================

export const permissions = pgTable(
    'permissions',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        organizationId: uuid('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),

        // Composite key: "users:profiles:read" or "users:*:read" or "*:*:*"
        key: varchar('key', { length: 255 }).notNull(),

        // Key components (denormalized for queries)
        namespace: varchar('namespace', { length: 63 }).notNull(),
        resource: varchar('resource', { length: 63 }).notNull(),
        action: varchar('action', { length: 63 }).notNull(),

        // Information
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
        // Unique key per organization
        uniqueIndex('permission_org_key_unique_idx')
            .on(table.organizationId, table.key)
            .where(sql`${table.deletedAt} IS NULL`),

        // Search by components (for wildcard matching)
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

        // Constraint: key = namespace:resource:action
        check(
            'permission_key_format',
            sql`${table.key} = ${table.namespace} || ':' || ${table.resource} || ':' || ${table.action}`
        ),

        // Constraint: valid characters
        check(
            'permission_components_format',
            sql`${table.namespace} ~ '^[a-z0-9_*]+$' AND ${table.resource} ~ '^[a-z0-9_*]+$' AND ${table.action} ~ '^[a-z0-9_*]+$'`
        ),
    ]
);

// ============================================================================
// ROLES (Permission groups)
// ============================================================================

export const roles = pgTable(
    'roles',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        organizationId: uuid('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),

        // Identifiers
        slug: varchar('slug', { length: 63 }).notNull(),
        name: varchar('name', { length: 255 }).notNull(),
        description: text('description'),

        // System
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
        // Unique slug per organization
        uniqueIndex('role_org_slug_unique_idx')
            .on(table.organizationId, table.slug)
            .where(sql`${table.deletedAt} IS NULL`),

        // Cleanup
        index('role_deleted_at_idx')
            .on(table.deletedAt)
            .where(sql`${table.deletedAt} IS NOT NULL`),

        // Constraint: slug format
        check(
            'role_slug_format',
            sql`${table.slug} ~ '^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$'`
        ),
    ]
);

// ============================================================================
// ROLE_PERMISSIONS (Junction table)
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
        // Uniqueness constraint
        uniqueIndex('role_permission_unique_idx').on(
            table.roleId,
            table.permissionId
        ),

        // Index for reverse lookup (permissions → roles)
        index('role_permission_perm_idx').on(table.permissionId),
    ]
);

// ============================================================================
// IDENTITY_ROLES (Roles assigned to identities)
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

        // Traceability
        grantedBy: uuid('granted_by').references(() => identities.id, {
            onDelete: 'set null',
        }),

        // Timestamps
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
        expiresAt: timestamp('expires_at', { withTimezone: true }), // Temporary roles
    },
    (table) => [
        // Uniqueness constraint
        uniqueIndex('identity_role_unique_idx').on(
            table.identityId,
            table.roleId
        ),

        // Index for reverse lookup
        index('identity_role_role_idx').on(table.roleId),

        // Index for temporary roles (cleanup)
        index('identity_role_expires_idx')
            .on(table.expiresAt)
            .where(sql`${table.expiresAt} IS NOT NULL`),

        // Constraint: expiration must be in the future
        check(
            'identity_role_expires_future',
            sql`${table.expiresAt} IS NULL OR ${table.expiresAt} > ${table.createdAt}`
        ),
    ]
);

// ============================================================================
// IDENTITY_PERMISSIONS (Direct permissions)
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

        // Traceability
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
        // Uniqueness constraint
        uniqueIndex('identity_permission_unique_idx').on(
            table.identityId,
            table.permissionId
        ),

        // Index for reverse lookup
        index('identity_permission_perm_idx').on(table.permissionId),

        // Index for temporary permissions
        index('identity_permission_expires_idx')
            .on(table.expiresAt)
            .where(sql`${table.expiresAt} IS NOT NULL`),

        // Constraint
        check(
            'identity_permission_expires_future',
            sql`${table.expiresAt} IS NULL OR ${table.expiresAt} > ${table.createdAt}`
        ),
    ]
);

// ============================================================================
// AUTH_METHOD_PERMISSIONS (Permissions for PATs/API keys)
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
        // Uniqueness constraint
        uniqueIndex('auth_method_permission_unique_idx').on(
            table.authMethodId,
            table.permissionId
        ),

        // Index for authMethod (listing permissions)
        index('auth_method_permission_method_idx').on(table.authMethodId),
    ]
);
