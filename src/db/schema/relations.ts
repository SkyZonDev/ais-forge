import { relations } from 'drizzle-orm';
import { auditLogs } from './audit';
import { authMethods, refreshTokens, sessions } from './auth';
import { identities } from './identities';
import { organizations } from './organizations';
import { rateLimits } from './rate-limits';
import {
    authMethodPermissions,
    identityPermissions,
    identityRoles,
    permissions,
    rolePermissions,
    roles,
} from './roles';

// ============================================================================
// RELATIONS DRIZZLE (Query Builder)
// ============================================================================

export const organizationsRelations = relations(organizations, ({ many }) => ({
    identities: many(identities),
    authMethods: many(authMethods),
    sessions: many(sessions),
    refreshTokens: many(refreshTokens),
    permissions: many(permissions),
    roles: many(roles),
    auditLogs: many(auditLogs),
    rateLimits: many(rateLimits),
}));

export const identitiesRelations = relations(identities, ({ one, many }) => ({
    organization: one(organizations, {
        fields: [identities.organizationId],
        references: [organizations.id],
    }),
    authMethods: many(authMethods),
    sessions: many(sessions),
    refreshTokens: many(refreshTokens),
    identityRoles: many(identityRoles),
    identityPermissions: many(identityPermissions),
    auditLogs: many(auditLogs),
    rateLimits: many(rateLimits),
    // Rôles/permissions accordés par cette identité
    grantedRoles: many(identityRoles, { relationName: 'grantedBy' }),
    grantedPermissions: many(identityPermissions, {
        relationName: 'grantedBy',
    }),
}));

export const authMethodsRelations = relations(authMethods, ({ one, many }) => ({
    identity: one(identities, {
        fields: [authMethods.identityId],
        references: [identities.id],
    }),
    organization: one(organizations, {
        fields: [authMethods.organizationId],
        references: [organizations.id],
    }),
    authMethodPermissions: many(authMethodPermissions),
    refreshTokens: many(refreshTokens),
    auditLogs: many(auditLogs),
}));

export const sessionsRelations = relations(sessions, ({ one, many }) => ({
    identity: one(identities, {
        fields: [sessions.identityId],
        references: [identities.id],
    }),
    organization: one(organizations, {
        fields: [sessions.organizationId],
        references: [organizations.id],
    }),
    refreshTokens: many(refreshTokens),
    auditLogs: many(auditLogs),
}));

export const refreshTokensRelations = relations(refreshTokens, ({ one }) => ({
    identity: one(identities, {
        fields: [refreshTokens.identityId],
        references: [identities.id],
    }),
    organization: one(organizations, {
        fields: [refreshTokens.organizationId],
        references: [organizations.id],
    }),
    session: one(sessions, {
        fields: [refreshTokens.sessionId],
        references: [sessions.id],
    }),
    authMethod: one(authMethods, {
        fields: [refreshTokens.authMethodId],
        references: [authMethods.id],
    }),
    parentToken: one(refreshTokens, {
        fields: [refreshTokens.parentTokenId],
        references: [refreshTokens.id],
        relationName: 'tokenChain',
    }),
}));

export const permissionsRelations = relations(permissions, ({ one, many }) => ({
    organization: one(organizations, {
        fields: [permissions.organizationId],
        references: [organizations.id],
    }),
    rolePermissions: many(rolePermissions),
    identityPermissions: many(identityPermissions),
    authMethodPermissions: many(authMethodPermissions),
}));

export const rolesRelations = relations(roles, ({ one, many }) => ({
    organization: one(organizations, {
        fields: [roles.organizationId],
        references: [organizations.id],
    }),
    rolePermissions: many(rolePermissions),
    identityRoles: many(identityRoles),
}));

export const rolePermissionsRelations = relations(
    rolePermissions,
    ({ one }) => ({
        role: one(roles, {
            fields: [rolePermissions.roleId],
            references: [roles.id],
        }),
        permission: one(permissions, {
            fields: [rolePermissions.permissionId],
            references: [permissions.id],
        }),
    })
);

export const identityRolesRelations = relations(identityRoles, ({ one }) => ({
    identity: one(identities, {
        fields: [identityRoles.identityId],
        references: [identities.id],
    }),
    role: one(roles, {
        fields: [identityRoles.roleId],
        references: [roles.id],
    }),
    grantedByIdentity: one(identities, {
        fields: [identityRoles.grantedBy],
        references: [identities.id],
        relationName: 'grantedBy',
    }),
}));

export const identityPermissionsRelations = relations(
    identityPermissions,
    ({ one }) => ({
        identity: one(identities, {
            fields: [identityPermissions.identityId],
            references: [identities.id],
        }),
        permission: one(permissions, {
            fields: [identityPermissions.permissionId],
            references: [permissions.id],
        }),
        grantedByIdentity: one(identities, {
            fields: [identityPermissions.grantedBy],
            references: [identities.id],
            relationName: 'grantedBy',
        }),
    })
);

export const authMethodPermissionsRelations = relations(
    authMethodPermissions,
    ({ one }) => ({
        authMethod: one(authMethods, {
            fields: [authMethodPermissions.authMethodId],
            references: [authMethods.id],
        }),
        permission: one(permissions, {
            fields: [authMethodPermissions.permissionId],
            references: [permissions.id],
        }),
    })
);

export const auditLogsRelations = relations(auditLogs, ({ one }) => ({
    organization: one(organizations, {
        fields: [auditLogs.organizationId],
        references: [organizations.id],
    }),
    identity: one(identities, {
        fields: [auditLogs.identityId],
        references: [identities.id],
    }),
    session: one(sessions, {
        fields: [auditLogs.sessionId],
        references: [sessions.id],
    }),
    authMethod: one(authMethods, {
        fields: [auditLogs.authMethodId],
        references: [authMethods.id],
    }),
}));

export const rateLimitsRelations = relations(rateLimits, ({ one }) => ({
    organization: one(organizations, {
        fields: [rateLimits.organizationId],
        references: [organizations.id],
    }),
    identity: one(identities, {
        fields: [rateLimits.identityId],
        references: [identities.id],
    }),
}));
