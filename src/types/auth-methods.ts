import * as schema from '../db/schema';
import { authMethodType } from '../db/schema/enum';
import type { Cursor } from './pagination';

/**
 * Represents a raw auth method record from the database.
 * This type is inferred from the Drizzle schema.
 */
type AuthMethod = typeof schema.authMethods.$inferSelect;

/**
 * Represents the data required to create a new auth method.
 * Excludes auto-generated fields (id, createdAt).
 */
type AuthMethodInsert = typeof schema.authMethods.$inferInsert;

/**
 * Supported auth method types for filtering queries.
 * Maps to the authMethodTypeEnum in the schema.
 */
type AuthMethodType = (typeof authMethodType)[number];

/**
 * Options for paginated queries on auth methods.
 */
interface AuthMethodPaginationOptions {
    /** Maximum number of items to return (default: 20) */
    limit?: number;
    /** Cursor for forward pagination (older records) */
    cursor?: Cursor;
    /** Whether to include revoked methods (default: false) */
    includeRevoked?: boolean;
    /** Whether to include expired methods (default: false) */
    includeExpired?: boolean;
}

/**
 * Options for updating auth method metadata.
 */
interface UpdateMetadataOptions {
    /** Merge with existing metadata (true) or replace entirely (false) */
    merge?: boolean;
}

/**
 * Result of a revocation operation.
 */
interface RevocationResult {
    /** Whether the revocation was successful */
    success: boolean;
    /** The revoked auth method, or null if not found */
    authMethod: AuthMethod | null;
    /** Reason for revocation failure, if any */
    error?: string;
}

/**
 * Statistics about auth methods for an identity.
 */
interface AuthMethodStats {
    /** Total number of auth methods */
    total: number;
    /** Number of active (non-revoked, non-expired) methods */
    active: number;
    /** Number of revoked methods */
    revoked: number;
    /** Number of expired methods */
    expired: number;
}

export type {
    AuthMethod,
    AuthMethodInsert,
    AuthMethodType,
    AuthMethodPaginationOptions,
    UpdateMetadataOptions,
    RevocationResult,
    AuthMethodStats,
};
