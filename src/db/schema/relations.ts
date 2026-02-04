import { relations } from 'drizzle-orm';
import { auditLogs } from './audit';
import { authMethods, refreshTokens, sessions } from './auth';
import { identities, identityOrganizations } from './identities';
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
// DRIZZLE RELATIONS (Query Builder)
// ============================================================================

export const organizationsRelations = relations(organizations, ({ many }) => ({
    // Multi-org membership
    identityOrganizations: many(identityOrganizations),

    // Auth
    authMethods: many(authMethods),
    sessions: many(sessions),
    refreshTokens: many(refreshTokens),

    // Permissions & Roles
    permissions: many(permissions),
    roles: many(roles),
    identityRoles: many(identityRoles),
    identityPermissions: many(identityPermissions),
    auditLogs: many(auditLogs),
    rateLimits: many(rateLimits),
}));

export const identitiesRelations = relations(identities, ({ one, many }) => ({
    // Multi-org membership
    organizationMemberships: many(identityOrganizations),

    // Auth (can have multiple per org)
    authMethods: many(authMethods),
    sessions: many(sessions),
    refreshTokens: many(refreshTokens),

    // Roles & Permissions (per org)
    identityRoles: many(identityRoles),
    identityPermissions: many(identityPermissions),

    // Traceability: Roles/permissions granted by this identity
    grantedRoles: many(identityRoles, { relationName: 'grantedBy' }),
    grantedPermissions: many(identityPermissions, {
        relationName: 'grantedBy',
    }),

    // Invitations sent
    invitedOrganizations: many(identityOrganizations, {
        relationName: 'invitedBy',
    }),
    auditLogs: many(auditLogs),
    rateLimits: many(rateLimits),
}));

export const identityOrganizationsRelations = relations(
    identityOrganizations,
    ({ one }) => ({
        identity: one(identities, {
            fields: [identityOrganizations.identityId],
            references: [identities.id],
        }),
        organization: one(organizations, {
            fields: [identityOrganizations.organizationId],
            references: [organizations.id],
        }),
        invitedByIdentity: one(identities, {
            fields: [identityOrganizations.invitedBy],
            references: [identities.id],
            relationName: 'invitedBy',
        }),
    })
);

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
    organization: one(organizations, {
        fields: [identityRoles.organizationId],
        references: [organizations.id],
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
        organization: one(organizations, {
            fields: [identityPermissions.organizationId],
            references: [organizations.id],
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
