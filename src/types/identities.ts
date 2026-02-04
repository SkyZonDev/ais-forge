import * as schema from '../db/schema';
import type { CursorPaginationOptions } from './pagination';

/** Identity type supported by the system */
export type IdentityType = 'human' | 'service' | 'machine';

/** Identity status */
export type IdentityStatus = 'active' | 'suspended' | 'deleted';

/** Fields returned for an identity (public view) */
export interface IdentityPublic {
    id: string;
    displayName: string;
    email: string | null;
}

/** Complete representation of an identity */
export interface Identity {
    id: string;
    type: IdentityType;
    status: IdentityStatus;
    displayName: string;
    email: string | null;
    createdAt: Date;
    updatedAt: Date;
    lastActivityAt: Date | null;
    deletedAt: Date | null;
    metadata: Record<string, unknown>;
}

/** Parameters for creating an identity */
export interface CreateIdentityParams {
    organizationId: string;
    displayName: string;
    email?: string | null;
    type?: IdentityType;
    status?: IdentityStatus;
    metadata?: Record<string, unknown>;
}

/** Parameters for creating a user with their organization */
export interface CreateUserWithOrganizationParams {
    displayName: string;
    email: string;
    credentialHash: string;
    organizationName: string;
    organizationSlug: string;
}

/** Result of creating a user with organization */
export interface CreateUserWithOrganizationResult {
    organization: typeof schema.organizations.$inferSelect;
    identity: typeof schema.identities.$inferSelect;
    authMethod: typeof schema.authMethods.$inferSelect;
}

/** Parameters for updating an identity */
export interface UpdateIdentityParams {
    displayName?: string;
    email?: string | null;
    status?: IdentityStatus;
    metadata?: Record<string, unknown>;
}

/** Filtering options for the list of identities */
export interface FindAllIdentitiesOptions extends CursorPaginationOptions {
    organizationId: string;
    type?: IdentityType;
    status?: IdentityStatus;
    search?: string;
    limit?: number;
    includeTotalCount: boolean;
}
