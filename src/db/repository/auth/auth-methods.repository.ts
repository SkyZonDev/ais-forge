import {
    and,
    asc,
    count,
    desc,
    eq,
    isNull,
    lt,
    or,
    SQL,
    sql,
} from 'drizzle-orm';
import type { RevocationResult } from '../../../types/auth';
import type {
    AuthMethod,
    AuthMethodInsert,
    AuthMethodPaginationOptions,
    AuthMethodStats,
    AuthMethodType,
    UpdateMetadataOptions,
} from '../../../types/auth-methods';
import { db } from '../../../utils/db';
import * as schema from '../../schema';
import {
    _buildPaginatedResult,
    buildCursorCondition,
    type Cursor,
    decodeCursor,
    type PaginatedResult,
} from '../utils';

// ============================================================================
// REPOSITORY
// ============================================================================

export const authMethodsRepository = {
    // ========================================================================
    // CREATE OPERATIONS
    // ========================================================================

    /**
     * Creates a new authentication method for an identity.
     *
     * This is the primary method for registering new credentials such as
     * passwords, API tokens, passkeys, or OAuth connections.
     *
     * @param data - The auth method data to insert
     * @returns The newly created auth method record
     * @throws {Error} If the insert operation fails (e.g., FK violation)
     *
     * @example
     * ```typescript
     * // Create a password auth method
     * const passwordHash = await hashPassword(plainPassword);
     * const authMethod = await authMethodsRepository.create({
     *   identityId: user.identityId,
     *   organizationId: user.organizationId,
     *   type: 'password',
     *   credentialHash: passwordHash,
     *   metadata: { passwordVersion: 1 },
     * });
     *
     * // Create an API token with expiration
     * const tokenHash = await hashToken(rawToken);
     * const apiKey = await authMethodsRepository.create({
     *   identityId: serviceAccount.identityId,
     *   organizationId: serviceAccount.organizationId,
     *   type: 'api_token',
     *   name: 'CI Pipeline Token',
     *   credentialHash: tokenHash,
     *   expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
     *   metadata: { scopes: ['read', 'write'], ipWhitelist: ['10.0.0.0/8'] },
     * });
     * ```
     *
     * @security
     * - NEVER store plain text passwords in credentialHash
     * - Use Argon2id for passwords, SHA-256 for tokens
     * - Always set appropriate expiresAt for temporary credentials
     */
    async create(data: AuthMethodInsert): Promise<AuthMethod> {
        const [authMethod] = await db
            .insert(schema.authMethods)
            .values(data)
            .returning();

        return authMethod!;
    },

    /**
     * Creates multiple authentication methods in a single transaction.
     *
     * Useful for batch operations like migrating credentials or setting up
     * initial auth methods for a new user.
     *
     * @param data - Array of auth method data to insert
     * @returns Array of newly created auth method records
     * @throws {Error} If any insert fails (entire transaction is rolled back)
     *
     * @example
     * ```typescript
     * // Set up initial auth methods for a new user
     * const authMethods = await authMethodsRepository.createMany([
     *   {
     *     identityId: user.identityId,
     *     organizationId: user.organizationId,
     *     type: 'password',
     *     credentialHash: passwordHash,
     *   },
     *   {
     *     identityId: user.identityId,
     *     organizationId: user.organizationId,
     *     type: 'totp',
     *     credentialHash: totpSecretHash,
     *     metadata: { verified: false },
     *   },
     * ]);
     * ```
     */
    async createMany(data: AuthMethodInsert[]): Promise<AuthMethod[]> {
        if (data.length === 0) return [];

        return db.insert(schema.authMethods).values(data).returning();
    },

    // ========================================================================
    // READ OPERATIONS - Single Record
    // ========================================================================

    /**
     * Finds an auth method by its unique identifier.
     *
     * @param id - The UUID of the auth method
     * @returns The auth method if found, null otherwise
     *
     * @example
     * ```typescript
     * const authMethod = await authMethodsRepository.findById(authMethodId);
     * if (!authMethod) {
     *   throw new NotFoundError('Auth method not found');
     * }
     * ```
     */
    async findById(id: string): Promise<AuthMethod | null> {
        const authMethod = await db.query.authMethods.findFirst({
            where: eq(schema.authMethods.id, id),
        });

        return authMethod ?? null;
    },

    /**
     * Finds an active (non-revoked, non-expired) auth method by ID.
     *
     * This is the preferred method for authentication flows where only
     * valid credentials should be accepted.
     *
     * @param id - The UUID of the auth method
     * @returns The active auth method if found and valid, null otherwise
     *
     * @example
     * ```typescript
     * const authMethod = await authMethodsRepository.findActiveById(authMethodId);
     * if (!authMethod) {
     *   throw new AuthenticationError('Invalid or expired credentials');
     * }
     * ```
     */
    async findActiveById(id: string): Promise<AuthMethod | null> {
        const now = new Date();

        const authMethod = await db.query.authMethods.findFirst({
            where: and(
                eq(schema.authMethods.id, id),
                isNull(schema.authMethods.revokedAt),
                or(
                    isNull(schema.authMethods.expiresAt),
                    lt(schema.authMethods.expiresAt, now)
                )
            ),
        });

        return authMethod ?? null;
    },

    /**
     * Finds an active auth method by identity ID and type.
     *
     * Used during authentication to locate the specific credential type
     * being used (e.g., password, passkey, TOTP).
     *
     * @param identityId - The identity's UUID
     * @param type - The auth method type to find
     * @returns The active auth method if found, null otherwise
     *
     * @example
     * ```typescript
     * // Find password for authentication
     * const passwordMethod = await authMethodsRepository.findActiveByIdentityAndType(
     *   identity.id,
     *   'password'
     * );
     *
     * if (!passwordMethod) {
     *   throw new AuthenticationError('No password configured');
     * }
     *
     * const isValid = await verifyPassword(passwordMethod.credentialHash, inputPassword);
     * ```
     */
    async findActiveByIdentityAndType(
        identityId: string,
        type: AuthMethodType
    ): Promise<AuthMethod | null> {
        const now = new Date();

        const authMethod = await db.query.authMethods.findFirst({
            where: and(
                eq(schema.authMethods.identityId, identityId),
                eq(schema.authMethods.type, type),
                isNull(schema.authMethods.revokedAt),
                or(
                    isNull(schema.authMethods.expiresAt),
                    lt(schema.authMethods.expiresAt, now)
                )
            ),
        });

        return authMethod ?? null;
    },

    // ========================================================================
    // READ OPERATIONS - Multiple Records
    // ========================================================================

    /**
     * Finds all auth methods for a specific identity with pagination.
     *
     * Results are ordered by creation date (newest first) and support
     * cursor-based pagination for efficient traversal of large result sets.
     *
     * @param identityId - The identity's UUID
     * @param options - Pagination and filtering options
     * @returns Paginated result with auth methods and navigation cursors
     *
     * @example
     * ```typescript
     * // Get first page of auth methods
     * const result = await authMethodsRepository.findByIdentityId(identity.id, {
     *   limit: 10,
     * });
     *
     * // Get next page using cursor
     * if (result.pagination.hasNextPage) {
     *   const nextPage = await authMethodsRepository.findByIdentityId(identity.id, {
     *     limit: 10,
     *     cursor: result.pagination.endCursor!,
     *   });
     * }
     *
     * // Include revoked methods for admin view
     * const allMethods = await authMethodsRepository.findByIdentityId(identity.id, {
     *   includeRevoked: true,
     *   includeExpired: true,
     * });
     * ```
     */
    async findByIdentityId(
        identityId: string,
        options: AuthMethodPaginationOptions = {}
    ): Promise<PaginatedResult<AuthMethod>> {
        const {
            limit = 20,
            cursor,
            includeRevoked = false,
            includeExpired = false,
        } = options;

        const conditions: SQL[] = [
            eq(schema.authMethods.identityId, identityId),
        ];

        // Add status filters
        if (!includeRevoked) {
            conditions.push(isNull(schema.authMethods.revokedAt));
        }

        if (!includeExpired) {
            const now = new Date();
            conditions.push(
                or(
                    isNull(schema.authMethods.expiresAt),
                    lt(schema.authMethods.expiresAt, now)
                )!
            );
        }

        // Add cursor condition for pagination
        if (cursor) {
            const decoded = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.authMethods, decoded, 'forward')
            );
        }

        // Fetch one extra to determine if there are more results
        const results = await db.query.authMethods.findMany({
            where: and(...conditions),
            orderBy: [
                desc(schema.authMethods.createdAt),
                desc(schema.authMethods.id),
            ],
            limit: limit + 1,
        });

        const hasMore = results.length > limit;
        const items = hasMore ? results.slice(0, limit) : results;

        return _buildPaginatedResult(items, {
            ...(cursor && { cursor }),
            direction: 'forward',
            hasMore,
        });
    },

    /**
     * Finds all auth methods for a specific organization with pagination.
     *
     * Useful for organization administrators to audit and manage all
     * credentials within their organization.
     *
     * @param organizationId - The organization's UUID
     * @param options - Pagination and filtering options
     * @returns Paginated result with auth methods and navigation cursors
     *
     * @example
     * ```typescript
     * // Audit all active credentials in organization
     * const credentials = await authMethodsRepository.findByOrganizationId(
     *   org.id,
     *   { limit: 50 }
     * );
     *
     * // Find all API tokens (including expired) for rotation audit
     * const apiTokens = await authMethodsRepository.findByOrganizationIdAndType(
     *   org.id,
     *   'api_token',
     *   { includeExpired: true }
     * );
     * ```
     */
    async findByOrganizationId(
        organizationId: string,
        options: AuthMethodPaginationOptions = {}
    ): Promise<PaginatedResult<AuthMethod>> {
        const {
            limit = 20,
            cursor,
            includeRevoked = false,
            includeExpired = false,
        } = options;

        const conditions: SQL[] = [
            eq(schema.authMethods.organizationId, organizationId),
        ];

        if (!includeRevoked) {
            conditions.push(isNull(schema.authMethods.revokedAt));
        }

        if (!includeExpired) {
            const now = new Date();
            conditions.push(
                or(
                    isNull(schema.authMethods.expiresAt),
                    lt(schema.authMethods.expiresAt, now)
                )!
            );
        }

        if (cursor) {
            const decoded = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.authMethods, decoded, 'forward')
            );
        }

        const results = await db.query.authMethods.findMany({
            where: and(...conditions),
            orderBy: [
                desc(schema.authMethods.createdAt),
                desc(schema.authMethods.id),
            ],
            limit: limit + 1,
        });

        const hasMore = results.length > limit;
        const items = hasMore ? results.slice(0, limit) : results;

        return _buildPaginatedResult(items, {
            ...(cursor && { cursor }),
            direction: 'forward',
            hasMore,
        });
    },

    /**
     * Finds all auth methods of a specific type for an identity.
     *
     * Returns all methods regardless of status (active, revoked, expired)
     * for complete visibility. Use for administrative interfaces.
     *
     * @param identityId - The identity's UUID
     * @param type - The auth method type to filter by
     * @returns Array of auth methods matching the criteria
     *
     * @example
     * ```typescript
     * // Find all passkeys for a user (for passkey management UI)
     * const passkeys = await authMethodsRepository.findByIdentityIdAndType(
     *   user.identityId,
     *   'passkey'
     * );
     *
     * // Display in UI with status badges
     * passkeys.forEach(passkey => {
     *   console.log(`${passkey.name}: ${passkey.revokedAt ? 'Revoked' : 'Active'}`);
     * });
     * ```
     */
    async findByIdentityIdAndType(
        identityId: string,
        type: AuthMethodType
    ): Promise<AuthMethod[]> {
        return db.query.authMethods.findMany({
            where: and(
                eq(schema.authMethods.identityId, identityId),
                eq(schema.authMethods.type, type)
            ),
            orderBy: [desc(schema.authMethods.createdAt)],
        });
    },

    /**
     * Finds all active auth methods for an identity.
     *
     * Returns only non-revoked, non-expired methods. Use for displaying
     * currently valid authentication options to users.
     *
     * @param identityId - The identity's UUID
     * @returns Array of active auth methods
     *
     * @example
     * ```typescript
     * // Get available auth methods for login prompt
     * const activeMethods = await authMethodsRepository.findActiveByIdentityId(
     *   identity.id
     * );
     *
     * // Determine available login options
     * const hasPassword = activeMethods.some(m => m.type === 'password');
     * const hasPasskey = activeMethods.some(m => m.type === 'passkey');
     * const hasTOTP = activeMethods.some(m => m.type === 'totp');
     * ```
     */
    async findActiveByIdentityId(identityId: string): Promise<AuthMethod[]> {
        const now = new Date();

        return db.query.authMethods.findMany({
            where: and(
                eq(schema.authMethods.identityId, identityId),
                isNull(schema.authMethods.revokedAt),
                or(
                    isNull(schema.authMethods.expiresAt),
                    lt(schema.authMethods.expiresAt, now)
                )
            ),
            orderBy: [desc(schema.authMethods.createdAt)],
        });
    },

    // ========================================================================
    // UPDATE OPERATIONS
    // ========================================================================

    /**
     * Updates the lastUsedAt timestamp for an auth method.
     *
     * Should be called after successful authentication to track credential
     * usage patterns and identify stale credentials.
     *
     * @param id - The UUID of the auth method
     * @returns The updated auth method, or null if not found
     *
     * @example
     * ```typescript
     * // After successful password authentication
     * const isValid = await verifyPassword(authMethod.credentialHash, password);
     * if (isValid) {
     *   await authMethodsRepository.updateLastUsedAt(authMethod.id);
     *   // Continue with session creation...
     * }
     * ```
     */
    async updateLastUsedAt(id: string): Promise<AuthMethod | null> {
        const [updated] = await db
            .update(schema.authMethods)
            .set({ lastUsedAt: new Date() })
            .where(eq(schema.authMethods.id, id))
            .returning();

        return updated ?? null;
    },

    /**
     * Updates the metadata for an auth method.
     *
     * Metadata can store flexible, type-specific data such as:
     * - API token scopes and IP whitelists
     * - Passkey public key and attestation data
     * - OAuth provider tokens and refresh tokens
     *
     * @param id - The UUID of the auth method
     * @param metadata - New metadata to apply
     * @param options - Update options (merge vs replace)
     * @returns The updated auth method, or null if not found
     *
     * @example
     * ```typescript
     * // Update API token scopes (merge with existing)
     * await authMethodsRepository.updateMetadata(
     *   apiToken.id,
     *   { scopes: ['read', 'write', 'admin'] },
     *   { merge: true }
     * );
     *
     * // Replace entire metadata (for OAuth token refresh)
     * await authMethodsRepository.updateMetadata(
     *   oauthMethod.id,
     *   {
     *     accessToken: newAccessToken,
     *     refreshToken: newRefreshToken,
     *     expiresAt: tokenExpiry,
     *   },
     *   { merge: false }
     * );
     * ```
     */
    async updateMetadata(
        id: string,
        metadata: Record<string, unknown>,
        options: UpdateMetadataOptions = {}
    ): Promise<AuthMethod | null> {
        const { merge = true } = options;

        if (merge) {
            // Merge with existing metadata using JSONB concatenation
            const [updated] = await db
                .update(schema.authMethods)
                .set({
                    metadata: sql`${schema.authMethods.metadata} || ${JSON.stringify(metadata)}::jsonb`,
                })
                .where(eq(schema.authMethods.id, id))
                .returning();

            return updated ?? null;
        }

        // Replace entire metadata
        const [updated] = await db
            .update(schema.authMethods)
            .set({ metadata })
            .where(eq(schema.authMethods.id, id))
            .returning();

        return updated ?? null;
    },

    /**
     * Updates the credential hash for an auth method.
     *
     * Used for password changes, token rotation, or credential updates.
     *
     * @param id - The UUID of the auth method
     * @param credentialHash - New hashed credential
     * @returns The updated auth method, or null if not found
     *
     * @example
     * ```typescript
     * // Change user password
     * const newHash = await hashPassword(newPassword);
     * const updated = await authMethodsRepository.updateCredentialHash(
     *   passwordMethod.id,
     *   newHash
     * );
     *
     * if (updated) {
     *   // Optionally revoke all other sessions
     *   await sessionRepository.revokeAllByIdentityId(identity.id);
     * }
     * ```
     *
     * @security
     * - Always hash credentials before calling this method
     * - Consider revoking existing sessions after credential change
     * - Log credential changes for security auditing
     */
    async updateCredentialHash(
        id: string,
        credentialHash: string
    ): Promise<AuthMethod | null> {
        const [updated] = await db
            .update(schema.authMethods)
            .set({ credentialHash })
            .where(eq(schema.authMethods.id, id))
            .returning();

        return updated ?? null;
    },

    /**
     * Updates the expiration date for an auth method.
     *
     * Useful for extending or shortening credential validity.
     *
     * @param id - The UUID of the auth method
     * @param expiresAt - New expiration date, or null for no expiration
     * @returns The updated auth method, or null if not found
     *
     * @example
     * ```typescript
     * // Extend API token by 30 days
     * const newExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
     * await authMethodsRepository.updateExpiresAt(apiToken.id, newExpiry);
     *
     * // Remove expiration (make permanent)
     * await authMethodsRepository.updateExpiresAt(apiToken.id, null);
     * ```
     */
    async updateExpiresAt(
        id: string,
        expiresAt: Date | null
    ): Promise<AuthMethod | null> {
        const [updated] = await db
            .update(schema.authMethods)
            .set({ expiresAt })
            .where(eq(schema.authMethods.id, id))
            .returning();

        return updated ?? null;
    },

    /**
     * Updates the display name for an auth method.
     *
     * @param id - The UUID of the auth method
     * @param name - New display name
     * @returns The updated auth method, or null if not found
     *
     * @example
     * ```typescript
     * // Rename passkey after device change
     * await authMethodsRepository.updateName(
     *   passkey.id,
     *   'MacBook Pro (Work)'
     * );
     * ```
     */
    async updateName(id: string, name: string): Promise<AuthMethod | null> {
        const [updated] = await db
            .update(schema.authMethods)
            .set({ name })
            .where(eq(schema.authMethods.id, id))
            .returning();

        return updated ?? null;
    },

    // ========================================================================
    // REVOCATION OPERATIONS
    // ========================================================================

    /**
     * Revokes an auth method, making it permanently unusable.
     *
     * Revocation is a soft-delete operation that preserves the record for
     * audit purposes. Revoked methods cannot be reactivated.
     *
     * @param id - The UUID of the auth method to revoke
     * @returns Revocation result with success status and auth method
     *
     * @example
     * ```typescript
     * // Revoke a compromised API token
     * const result = await authMethodsRepository.revoke(compromisedToken.id);
     *
     * if (result.success) {
     *   logger.security('API token revoked', {
     *     authMethodId: result.authMethod!.id,
     *     identityId: result.authMethod!.identityId,
     *   });
     * }
     *
     * // Handle already revoked
     * if (result.error === 'already_revoked') {
     *   // Token was already revoked, no action needed
     * }
     * ```
     */
    async revoke(id: string): Promise<RevocationResult<AuthMethod>> {
        // Check current state
        const existing = await this.findById(id);

        if (!existing) {
            return { success: false, data: null, error: 'not_found' };
        }

        if (existing.revokedAt) {
            return {
                success: false,
                data: existing,
                error: 'already_revoked',
            };
        }

        const [revoked] = await db
            .update(schema.authMethods)
            .set({ revokedAt: new Date() })
            .where(eq(schema.authMethods.id, id))
            .returning();

        return { success: true, data: revoked! };
    },

    /**
     * Revokes all auth methods for an identity.
     *
     * Use when an account is compromised or during account deactivation.
     * This is a critical security operation.
     *
     * @param identityId - The identity's UUID
     * @returns Number of auth methods revoked
     *
     * @example
     * ```typescript
     * // Compromise response: revoke all credentials
     * const revokedCount = await authMethodsRepository.revokeAllByIdentityId(
     *   compromisedIdentity.id
     * );
     *
     * logger.security('All credentials revoked for identity', {
     *   identityId: compromisedIdentity.id,
     *   count: revokedCount,
     *   reason: 'account_compromise',
     * });
     *
     * // Force user to re-authenticate with new credentials
     * ```
     *
     * @security
     * - Log this operation for security auditing
     * - Notify the user through a separate channel if possible
     * - Invalidate all active sessions after revocation
     */
    async revokeAllByIdentityId(identityId: string): Promise<number> {
        const result = await db
            .update(schema.authMethods)
            .set({ revokedAt: new Date() })
            .where(
                and(
                    eq(schema.authMethods.identityId, identityId),
                    isNull(schema.authMethods.revokedAt)
                )
            )
            .returning({ id: schema.authMethods.id });

        return result.length;
    },

    /**
     * Revokes all auth methods of a specific type for an identity.
     *
     * Useful for targeted credential rotation or type-specific security events.
     *
     * @param identityId - The identity's UUID
     * @param type - The auth method type to revoke
     * @returns Number of auth methods revoked
     *
     * @example
     * ```typescript
     * // Revoke all API tokens during security audit
     * const revokedCount = await authMethodsRepository.revokeAllByIdentityIdAndType(
     *   identity.id,
     *   'api_token'
     * );
     *
     * // Force password reset
     * await authMethodsRepository.revokeAllByIdentityIdAndType(
     *   identity.id,
     *   'password'
     * );
     * ```
     */
    async revokeAllByIdentityIdAndType(
        identityId: string,
        type: AuthMethodType
    ): Promise<number> {
        const result = await db
            .update(schema.authMethods)
            .set({ revokedAt: new Date() })
            .where(
                and(
                    eq(schema.authMethods.identityId, identityId),
                    eq(schema.authMethods.type, type),
                    isNull(schema.authMethods.revokedAt)
                )
            )
            .returning({ id: schema.authMethods.id });

        return result.length;
    },

    // ========================================================================
    // DELETE OPERATIONS
    // ========================================================================

    /**
     * Permanently deletes an auth method from the database.
     *
     * @param id - The UUID of the auth method to delete
     * @returns True if deleted, false if not found
     *
     * @example
     * ```typescript
     * // Hard delete during GDPR data erasure
     * const deleted = await authMethodsRepository.deleteById(authMethod.id);
     * ```
     *
     * @warning
     * This is a hard delete operation. Consider using `revoke()` instead
     * to preserve audit trails. Use only for:
     * - GDPR/CCPA data erasure requests
     * - Cleanup of test data
     * - Regulatory compliance requirements
     */
    async deleteById(id: string): Promise<boolean> {
        const result = await db
            .delete(schema.authMethods)
            .where(eq(schema.authMethods.id, id))
            .returning({ id: schema.authMethods.id });

        return result.length > 0;
    },

    /**
     * Deletes all revoked auth methods older than a specified date.
     *
     * Use as part of a scheduled cleanup job to remove stale records
     * while maintaining recent audit history.
     *
     * @param olderThan - Delete records revoked before this date
     * @returns Number of records deleted
     *
     * @example
     * ```typescript
     * // Cleanup revoked methods older than 90 days
     * const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
     * const deletedCount = await authMethodsRepository.deleteRevokedBefore(
     *   ninetyDaysAgo
     * );
     *
     * logger.info('Cleaned up revoked auth methods', { count: deletedCount });
     * ```
     */
    async deleteRevokedBefore(olderThan: Date): Promise<number> {
        const result = await db
            .delete(schema.authMethods)
            .where(
                and(
                    lt(schema.authMethods.revokedAt, olderThan),
                    sql`${schema.authMethods.revokedAt} IS NOT NULL`
                )
            )
            .returning({ id: schema.authMethods.id });

        return result.length;
    },

    /**
     * Deletes all expired auth methods older than a specified date.
     *
     * Use as part of a scheduled cleanup job. Expired methods that have
     * not been used recently can be safely removed.
     *
     * @param olderThan - Delete records expired before this date
     * @returns Number of records deleted
     *
     * @example
     * ```typescript
     * // Cleanup expired methods older than 30 days
     * const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
     * const deletedCount = await authMethodsRepository.deleteExpiredBefore(
     *   thirtyDaysAgo
     * );
     * ```
     */
    async deleteExpiredBefore(olderThan: Date): Promise<number> {
        const result = await db
            .delete(schema.authMethods)
            .where(
                and(
                    lt(schema.authMethods.expiresAt, olderThan),
                    sql`${schema.authMethods.expiresAt} IS NOT NULL`
                )
            )
            .returning({ id: schema.authMethods.id });

        return result.length;
    },

    // ========================================================================
    // COUNT & STATISTICS
    // ========================================================================

    /**
     * Counts auth methods for an identity with optional filtering.
     *
     * @param identityId - The identity's UUID
     * @param options - Filtering options
     * @returns Total count of matching auth methods
     *
     * @example
     * ```typescript
     * // Count all auth methods
     * const total = await authMethodsRepository.countByIdentityId(identity.id);
     *
     * // Count only active methods
     * const active = await authMethodsRepository.countByIdentityId(identity.id, {
     *   includeRevoked: false,
     *   includeExpired: false,
     * });
     * ```
     */
    async countByIdentityId(
        identityId: string,
        options: { includeRevoked?: boolean; includeExpired?: boolean } = {}
    ): Promise<number> {
        const { includeRevoked = true, includeExpired = true } = options;

        const conditions: SQL[] = [
            eq(schema.authMethods.identityId, identityId),
        ];

        if (!includeRevoked) {
            conditions.push(isNull(schema.authMethods.revokedAt));
        }

        if (!includeExpired) {
            const now = new Date();
            conditions.push(
                or(
                    isNull(schema.authMethods.expiresAt),
                    lt(schema.authMethods.expiresAt, now)
                )!
            );
        }

        const [result] = await db
            .select({ count: count() })
            .from(schema.authMethods)
            .where(and(...conditions));

        return result?.count ?? 0;
    },

    /**
     * Gets comprehensive statistics about auth methods for an identity.
     *
     * Provides counts broken down by status (active, revoked, expired)
     * for dashboard displays and security auditing.
     *
     * @param identityId - The identity's UUID
     * @returns Statistics object with counts by status
     *
     * @example
     * ```typescript
     * const stats = await authMethodsRepository.getStatsByIdentityId(identity.id);
     *
     * console.log(`Total: ${stats.total}`);
     * console.log(`Active: ${stats.active}`);
     * console.log(`Revoked: ${stats.revoked}`);
     * console.log(`Expired: ${stats.expired}`);
     * ```
     */
    async getStatsByIdentityId(identityId: string): Promise<AuthMethodStats> {
        const now = new Date();

        const [result] = await db
            .select({
                total: count(),
                revoked: count(schema.authMethods.revokedAt),
                expired: sql<number>`COUNT(CASE
                    WHEN ${schema.authMethods.expiresAt} IS NOT NULL
                    AND ${schema.authMethods.expiresAt} < ${now}
                    AND ${schema.authMethods.revokedAt} IS NULL
                    THEN 1
                END)`,
                active: sql<number>`COUNT(CASE
                    WHEN ${schema.authMethods.revokedAt} IS NULL
                    AND (${schema.authMethods.expiresAt} IS NULL OR ${schema.authMethods.expiresAt} >= ${now})
                    THEN 1
                END)`,
            })
            .from(schema.authMethods)
            .where(eq(schema.authMethods.identityId, identityId));

        return {
            total: result?.total ?? 0,
            active: Number(result?.active ?? 0),
            revoked: result?.revoked ?? 0,
            expired: Number(result?.expired ?? 0),
        };
    },

    /**
     * Checks if an identity has any active auth method of a specific type.
     *
     * Useful for validation checks (e.g., ensuring a user has a password
     * before allowing password-based login).
     *
     * @param identityId - The identity's UUID
     * @param type - The auth method type to check
     * @returns True if an active method of the type exists
     *
     * @example
     * ```typescript
     * // Check if user can use password login
     * const hasPassword = await authMethodsRepository.hasActiveMethodOfType(
     *   identity.id,
     *   'password'
     * );
     *
     * if (!hasPassword) {
     *   // Prompt user to set up password or use alternative auth
     * }
     * ```
     */
    async hasActiveMethodOfType(
        identityId: string,
        type: AuthMethodType
    ): Promise<boolean> {
        const method = await this.findActiveByIdentityAndType(identityId, type);
        return method !== null;
    },

    // ========================================================================
    // SECURITY & AUDIT
    // ========================================================================

    /**
     * Finds auth methods that haven't been used in a specified period.
     *
     * Use for security auditing to identify potentially abandoned or
     * compromised credentials that should be reviewed or revoked.
     *
     * @param organizationId - The organization's UUID
     * @param unusedSince - Find methods not used since this date
     * @param options - Pagination options
     * @returns Paginated result of stale auth methods
     *
     * @example
     * ```typescript
     * // Find credentials unused for 90 days
     * const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
     * const staleCredentials = await authMethodsRepository.findUnusedSince(
     *   org.id,
     *   ninetyDaysAgo
     * );
     *
     * // Send notifications to owners
     * for (const cred of staleCredentials.data) {
     *   await notificationService.sendStaleCredentialWarning(cred);
     * }
     * ```
     */
    async findUnusedSince(
        organizationId: string,
        unusedSince: Date,
        options: AuthMethodPaginationOptions = {}
    ): Promise<PaginatedResult<AuthMethod>> {
        const { limit = 20, cursor } = options;

        const conditions: SQL[] = [
            eq(schema.authMethods.organizationId, organizationId),
            isNull(schema.authMethods.revokedAt),
            or(
                isNull(schema.authMethods.lastUsedAt),
                lt(schema.authMethods.lastUsedAt, unusedSince)
            )!,
        ];

        if (cursor) {
            const decoded = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.authMethods, decoded, 'forward')
            );
        }

        const results = await db.query.authMethods.findMany({
            where: and(...conditions),
            orderBy: [
                desc(schema.authMethods.createdAt),
                desc(schema.authMethods.id),
            ],
            limit: limit + 1,
        });

        const hasMore = results.length > limit;
        const items = hasMore ? results.slice(0, limit) : results;

        return _buildPaginatedResult(items, {
            ...(cursor && { cursor }),
            direction: 'forward',
            hasMore,
        });
    },

    /**
     * Finds auth methods expiring within a specified period.
     *
     * Use for proactive notifications to credential owners before
     * their credentials expire.
     *
     * @param organizationId - The organization's UUID
     * @param withinDays - Number of days until expiration
     * @returns Array of auth methods expiring soon
     *
     * @example
     * ```typescript
     * // Find credentials expiring in next 7 days
     * const expiringCredentials = await authMethodsRepository.findExpiringSoon(
     *   org.id,
     *   7
     * );
     *
     * // Send renewal reminders
     * for (const cred of expiringCredentials) {
     *   await notificationService.sendExpirationWarning(cred);
     * }
     * ```
     */
    async findExpiringSoon(
        organizationId: string,
        withinDays: number
    ): Promise<AuthMethod[]> {
        const now = new Date();
        const futureDate = new Date(
            now.getTime() + withinDays * 24 * 60 * 60 * 1000
        );

        return db.query.authMethods.findMany({
            where: and(
                eq(schema.authMethods.organizationId, organizationId),
                isNull(schema.authMethods.revokedAt),
                sql`${schema.authMethods.expiresAt} IS NOT NULL`,
                lt(schema.authMethods.expiresAt, now),
                lt(schema.authMethods.expiresAt, futureDate)
            ),
            orderBy: [asc(schema.authMethods.expiresAt)],
        });
    },
};
