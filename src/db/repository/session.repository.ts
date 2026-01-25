import {
    and,
    asc,
    count,
    desc,
    eq,
    gt,
    isNull,
    lt,
    type SQL,
    sql,
} from 'drizzle-orm';
import type { RevocationResult, RevokedReason } from '../../types/auth';
import type {
    Session,
    SessionInsert,
    SessionPaginationOptions,
    SessionStats,
    UpdateMetadataOptions,
} from '../../types/sessions';
import { db, redis } from '../../utils/db';
import * as schema from '../schema';
import {
    _buildPaginatedResult,
    buildCursorCondition,
    decodeCursor,
    type PaginatedResult,
} from './utils';

// ============================================================================
// CONSTANTS
// ============================================================================

/** Redis key prefix for session cache */
const SESSION_CACHE_PREFIX = 'session:';

/** Redis key prefix for identity's active sessions set */
const IDENTITY_SESSIONS_PREFIX = 'identity:sessions:';

/** Default session cache TTL in seconds (15 minutes) */
const SESSION_CACHE_TTL = 900;

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/**
 * Generates the Redis cache key for a session token hash.
 *
 * @param tokenHash - The session token hash
 * @returns Redis key string
 * @internal
 */
function _getSessionCacheKey(tokenHash: string): string {
    return `${SESSION_CACHE_PREFIX}${tokenHash}`;
}

/**
 * Generates the Redis key for an identity's active sessions set.
 *
 * @param identityId - The identity's UUID
 * @returns Redis key string
 * @internal
 */
function _getIdentitySessionsKey(identityId: string): string {
    return `${IDENTITY_SESSIONS_PREFIX}${identityId}`;
}

/**
 * Caches a session in Redis for fast lookup.
 *
 * @param session - The session to cache
 * @internal
 */
async function _cacheSession(session: Session): Promise<void> {
    const key = _getSessionCacheKey(session.sessionTokenHash);
    const ttl = Math.min(
        SESSION_CACHE_TTL,
        Math.floor((session.expiresAt.getTime() - Date.now()) / 1000)
    );

    if (ttl > 0) {
        await redis.setex(key, ttl, JSON.stringify(session));
    }
}

/**
 * Invalidates a session from Redis cache.
 *
 * @param tokenHash - The session token hash to invalidate
 * @internal
 */
async function _invalidateSessionCache(tokenHash: string): Promise<void> {
    await redis.del(_getSessionCacheKey(tokenHash));
}

/**
 * Invalidates all cached sessions for an identity.
 *
 * @param identityId - The identity's UUID
 * @internal
 */
async function _invalidateIdentitySessions(identityId: string): Promise<void> {
    const key = _getIdentitySessionsKey(identityId);
    const sessionHashes = await redis.smembers(key);

    if (sessionHashes.length > 0) {
        const cacheKeys = sessionHashes.map((hash) =>
            _getSessionCacheKey(hash)
        );
        await redis.del(...cacheKeys, key);
    }
}

// ============================================================================
// REPOSITORY
// ============================================================================

export const sessionsRepository = {
    // ========================================================================
    // CREATE OPERATIONS
    // ========================================================================

    /**
     * Creates a new session for an identity.
     *
     * Sessions represent authenticated user sessions and are created after
     * successful authentication. Each session has a unique token hash for
     * lookup and a token family ID for theft detection.
     *
     * @param data - The session data to insert
     * @returns The newly created session record
     * @throws {Error} If the insert operation fails (e.g., FK violation, duplicate token)
     *
     * @example
     * ```typescript
     * // Create a session after successful login
     * const sessionToken = crypto.randomBytes(32).toString('base64url');
     * const tokenHash = await hashToken(sessionToken);
     *
     * const session = await sessionsRepository.create({
     *   identityId: user.identityId,
     *   organizationId: user.organizationId,
     *   tokenFamilyId: crypto.randomUUID(),
     *   sessionTokenHash: tokenHash,
     *   ipAddress: req.ip,
     *   userAgent: req.headers['user-agent'],
     *   expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
     *   metadata: {
     *     deviceType: 'desktop',
     *     browser: 'Chrome',
     *     os: 'macOS',
     *   },
     * });
     *
     * // Return plain token to client (only time it's available)
     * return { sessionToken, sessionId: session.id };
     * ```
     *
     * @security
     * - NEVER store plain session tokens, only hashed values
     * - Use cryptographically secure random tokens (min 256 bits)
     * - Set appropriate expiration based on security requirements
     * - Track IP and user agent for anomaly detection
     */
    async create(data: SessionInsert): Promise<Session> {
        const [session] = await db
            .insert(schema.sessions)
            .values(data)
            .returning();

        const created = session!;

        // Cache for fast token lookup
        await _cacheSession(created);

        // Track in identity's session set
        await redis.sadd(
            _getIdentitySessionsKey(created.identityId),
            created.sessionTokenHash
        );

        return created;
    },

    /**
     * Creates multiple sessions in a single transaction.
     *
     * Useful for batch operations like session migration or testing.
     *
     * @param data - Array of session data to insert
     * @returns Array of newly created session records
     * @throws {Error} If any insert fails (entire transaction is rolled back)
     *
     * @example
     * ```typescript
     * // Migrate sessions from legacy system
     * const sessions = await sessionsRepository.createMany(
     *   legacySessions.map(legacy => ({
     *     identityId: userMapping[legacy.userId],
     *     organizationId: orgId,
     *     tokenFamilyId: crypto.randomUUID(),
     *     sessionTokenHash: legacy.tokenHash,
     *     ipAddress: legacy.ip,
     *     expiresAt: legacy.expiry,
     *   }))
     * );
     * ```
     */
    async createMany(data: SessionInsert[]): Promise<Session[]> {
        if (data.length === 0) return [];

        const sessions = await db
            .insert(schema.sessions)
            .values(data)
            .returning();

        // Cache all sessions
        await Promise.all(
            sessions.map(async (session) => {
                await _cacheSession(session);
                await redis.sadd(
                    _getIdentitySessionsKey(session.identityId),
                    session.sessionTokenHash
                );
            })
        );

        return sessions;
    },

    // ========================================================================
    // READ OPERATIONS - Single Record
    // ========================================================================

    /**
     * Finds a session by its unique identifier.
     *
     * @param id - The UUID of the session
     * @returns The session if found, null otherwise
     *
     * @example
     * ```typescript
     * const session = await sessionsRepository.findById(sessionId);
     * if (!session) {
     *   throw new NotFoundError('Session not found');
     * }
     * ```
     */
    async findById(id: string): Promise<Session | null> {
        const session = await db.query.sessions.findFirst({
            where: eq(schema.sessions.id, id),
        });

        return session ?? null;
    },

    /**
     * Finds an active (non-revoked, non-expired) session by ID.
     *
     * This is the preferred method for session validation where only
     * valid sessions should be accepted.
     *
     * @param id - The UUID of the session
     * @returns The active session if found and valid, null otherwise
     *
     * @example
     * ```typescript
     * const session = await sessionsRepository.findActiveById(sessionId);
     * if (!session) {
     *   throw new UnauthorizedError('Session invalid or expired');
     * }
     * ```
     */
    async findActiveById(id: string): Promise<Session | null> {
        const now = new Date();

        const session = await db.query.sessions.findFirst({
            where: and(
                eq(schema.sessions.id, id),
                isNull(schema.sessions.revokedAt),
                gt(schema.sessions.expiresAt, now)
            ),
        });

        return session ?? null;
    },

    /**
     * Finds an active session by its token hash.
     *
     * This is the primary authentication method - used to validate session
     * tokens on every authenticated request. Uses Redis caching for performance.
     *
     * @param tokenHash - The SHA-256 hash of the session token
     * @returns The active session if valid, null otherwise
     *
     * @example
     * ```typescript
     * // Middleware: validate session token
     * async function validateSession(req: Request): Promise<Session> {
     *   const token = extractBearerToken(req);
     *   const tokenHash = await hashToken(token);
     *
     *   const session = await sessionsRepository.findActiveByTokenHash(tokenHash);
     *
     *   if (!session) {
     *     throw new UnauthorizedError('Invalid session');
     *   }
     *
     *   // Update activity timestamp asynchronously
     *   sessionsRepository.updateLastActivityAt(session.id).catch(console.error);
     *
     *   return session;
     * }
     * ```
     *
     * @performance
     * This method uses Redis caching to minimize database load.
     * Cache hit ratio should be monitored in production.
     */
    async findActiveByTokenHash(tokenHash: string): Promise<Session | null> {
        const now = new Date();

        // Try cache first
        const cached = await redis.get(_getSessionCacheKey(tokenHash));
        if (cached) {
            const session = JSON.parse(cached) as Session;

            // Parse date strings back to Date objects
            session.createdAt = new Date(session.createdAt);
            session.expiresAt = new Date(session.expiresAt);
            session.lastActivityAt = new Date(session.lastActivityAt);
            if (session.revokedAt)
                session.revokedAt = new Date(session.revokedAt);

            // Validate cached session is still active
            if (!session.revokedAt && session.expiresAt > now) {
                return session;
            }

            // Cached session is no longer valid, remove from cache
            await _invalidateSessionCache(tokenHash);
        }

        // Cache miss or invalid - query database
        const session = await db.query.sessions.findFirst({
            where: and(
                eq(schema.sessions.sessionTokenHash, tokenHash),
                isNull(schema.sessions.revokedAt),
                gt(schema.sessions.expiresAt, now)
            ),
        });

        if (session) {
            await _cacheSession(session);
        }

        return session ?? null;
    },

    // ========================================================================
    // READ OPERATIONS - Multiple Records
    // ========================================================================

    /**
     * Finds all sessions for a specific identity with pagination.
     *
     * Results are ordered by creation date (newest first) and support
     * cursor-based pagination for efficient traversal of large result sets.
     *
     * @param identityId - The identity's UUID
     * @param options - Pagination and filtering options
     * @returns Paginated result with sessions and navigation cursors
     *
     * @example
     * ```typescript
     * // Get first page of active sessions
     * const result = await sessionsRepository.findByIdentityId(identity.id, {
     *   limit: 10,
     * });
     *
     * // Display sessions in security dashboard
     * result.data.forEach(session => {
     *   console.log(`${session.ipAddress} - ${session.userAgent}`);
     *   console.log(`Last active: ${session.lastActivityAt}`);
     * });
     *
     * // Get next page using cursor
     * if (result.pagination.hasNextPage) {
     *   const nextPage = await sessionsRepository.findByIdentityId(identity.id, {
     *     limit: 10,
     *     cursor: result.pagination.endCursor!,
     *   });
     * }
     * ```
     */
    async findByIdentityId(
        identityId: string,
        options: SessionPaginationOptions = {}
    ): Promise<PaginatedResult<Session>> {
        const { limit = 20, cursor, includeRevoked = false } = options;

        const conditions: SQL[] = [eq(schema.sessions.identityId, identityId)];

        if (!includeRevoked) {
            conditions.push(isNull(schema.sessions.revokedAt));
        }

        if (cursor) {
            const decoded = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.sessions, decoded, 'forward')
            );
        }

        const results = await db.query.sessions.findMany({
            where: and(...conditions),
            orderBy: [
                desc(schema.sessions.createdAt),
                desc(schema.sessions.id),
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
     * Finds all sessions for a specific organization with pagination.
     *
     * Useful for organization administrators to audit and manage all
     * active sessions within their organization.
     *
     * @param organizationId - The organization's UUID
     * @param options - Pagination and filtering options
     * @returns Paginated result with sessions and navigation cursors
     *
     * @example
     * ```typescript
     * // Security audit: view all active sessions
     * const sessions = await sessionsRepository.findByOrganizationId(
     *   org.id,
     *   { limit: 50 }
     * );
     *
     * // Identify suspicious patterns
     * const byIp = sessions.data.reduce((acc, s) => {
     *   acc[s.ipAddress] = (acc[s.ipAddress] || 0) + 1;
     *   return acc;
     * }, {} as Record<string, number>);
     * ```
     */
    async findByOrganizationId(
        organizationId: string,
        options: SessionPaginationOptions = {}
    ): Promise<PaginatedResult<Session>> {
        const { limit = 20, cursor, includeRevoked = false } = options;

        const conditions: SQL[] = [
            eq(schema.sessions.organizationId, organizationId),
        ];

        if (!includeRevoked) {
            conditions.push(isNull(schema.sessions.revokedAt));
        }

        if (cursor) {
            const decoded = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.sessions, decoded, 'forward')
            );
        }

        const results = await db.query.sessions.findMany({
            where: and(...conditions),
            orderBy: [
                desc(schema.sessions.createdAt),
                desc(schema.sessions.id),
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
     * Finds all active sessions for an identity.
     *
     * Returns only non-revoked, non-expired sessions. Use for displaying
     * currently active sessions to users in their security settings.
     *
     * @param identityId - The identity's UUID
     * @returns Array of active sessions
     *
     * @example
     * ```typescript
     * // Display active sessions in user security settings
     * const activeSessions = await sessionsRepository.findActiveByIdentityId(
     *   identity.id
     * );
     *
     * // Mark current session
     * const sessionsWithCurrent = activeSessions.map(s => ({
     *   ...s,
     *   isCurrent: s.id === currentSessionId,
     * }));
     * ```
     */
    async findActiveByIdentityId(identityId: string): Promise<Session[]> {
        const now = new Date();

        return db.query.sessions.findMany({
            where: and(
                eq(schema.sessions.identityId, identityId),
                isNull(schema.sessions.revokedAt),
                gt(schema.sessions.expiresAt, now)
            ),
            orderBy: [desc(schema.sessions.lastActivityAt)],
        });
    },

    /**
     * Finds all sessions in a token family.
     *
     * Used for theft detection - when a refresh token is reused, all
     * sessions in the family should be investigated or revoked.
     *
     * @param tokenFamilyId - The token family UUID
     * @returns Array of sessions in the family
     *
     * @example
     * ```typescript
     * // Theft detection: refresh token reuse detected
     * const familySessions = await sessionsRepository.findByTokenFamilyId(
     *   tokenFamilyId
     * );
     *
     * // Revoke all sessions in family (potential theft)
     * await sessionsRepository.revokeByTokenFamilyId(tokenFamilyId, 'stolen');
     *
     * logger.security('Token reuse detected - family revoked', {
     *   tokenFamilyId,
     *   affectedSessions: familySessions.length,
     * });
     * ```
     *
     * @security
     * Token family tracking is critical for detecting refresh token theft.
     * If a token is used after rotation, the entire family is compromised.
     */
    async findByTokenFamilyId(tokenFamilyId: string): Promise<Session[]> {
        return db.query.sessions.findMany({
            where: eq(schema.sessions.tokenFamilyId, tokenFamilyId),
            orderBy: [desc(schema.sessions.createdAt)],
        });
    },

    /**
     * Finds sessions by IP address for an organization.
     *
     * Useful for security analysis and identifying suspicious activity
     * from specific IP addresses.
     *
     * @param organizationId - The organization's UUID
     * @param ipAddress - The IP address to search for
     * @param options - Pagination options
     * @returns Paginated result of sessions from the IP
     *
     * @example
     * ```typescript
     * // Investigate suspicious IP
     * const sessions = await sessionsRepository.findByIpAddress(
     *   org.id,
     *   suspiciousIp
     * );
     *
     * // Check if multiple identities accessed from same IP
     * const identities = new Set(sessions.data.map(s => s.identityId));
     * if (identities.size > 10) {
     *   logger.security('Possible credential stuffing attack', {
     *     ip: suspiciousIp,
     *     uniqueIdentities: identities.size,
     *   });
     * }
     * ```
     */
    async findByIpAddress(
        organizationId: string,
        ipAddress: string,
        options: SessionPaginationOptions = {}
    ): Promise<PaginatedResult<Session>> {
        const { limit = 20, cursor, includeRevoked = false } = options;

        const conditions: SQL[] = [
            eq(schema.sessions.organizationId, organizationId),
            eq(schema.sessions.ipAddress, ipAddress),
        ];

        if (!includeRevoked) {
            conditions.push(isNull(schema.sessions.revokedAt));
        }

        if (cursor) {
            const decoded = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.sessions, decoded, 'forward')
            );
        }

        const results = await db.query.sessions.findMany({
            where: and(...conditions),
            orderBy: [
                desc(schema.sessions.createdAt),
                desc(schema.sessions.id),
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

    // ========================================================================
    // UPDATE OPERATIONS
    // ========================================================================

    /**
     * Updates the lastActivityAt timestamp for a session.
     *
     * Should be called periodically during active use to track session
     * activity. Useful for identifying idle sessions and security monitoring.
     *
     * @param id - The UUID of the session
     * @returns The updated session, or null if not found
     *
     * @example
     * ```typescript
     * // Update activity on authenticated requests (fire-and-forget)
     * sessionsRepository.updateLastActivityAt(session.id).catch(err => {
     *   logger.error('Failed to update session activity', { error: err });
     * });
     * ```
     *
     * @performance
     * Consider batching activity updates or using a rate limit
     * to avoid excessive database writes on high-traffic endpoints.
     */
    async updateLastActivityAt(id: string): Promise<Session | null> {
        const [updated] = await db
            .update(schema.sessions)
            .set({ lastActivityAt: new Date() })
            .where(eq(schema.sessions.id, id))
            .returning();

        if (updated) {
            await _cacheSession(updated);
        }

        return updated ?? null;
    },

    /**
     * Updates the metadata for a session.
     *
     * Metadata can store session-specific data such as:
     * - Device information (type, browser, OS)
     * - Geolocation data
     * - Feature flags or preferences
     * - Security context (trust level, verification status)
     *
     * @param id - The UUID of the session
     * @param metadata - New metadata to apply
     * @param options - Update options (merge vs replace)
     * @returns The updated session, or null if not found
     *
     * @example
     * ```typescript
     * // Add geolocation after async lookup
     * await sessionsRepository.updateMetadata(
     *   session.id,
     *   {
     *     geo: {
     *       country: 'US',
     *       region: 'CA',
     *       city: 'San Francisco',
     *     },
     *   },
     *   { merge: true }
     * );
     *
     * // Mark session as MFA-verified
     * await sessionsRepository.updateMetadata(
     *   session.id,
     *   { mfaVerified: true, mfaMethod: 'totp' },
     *   { merge: true }
     * );
     * ```
     */
    async updateMetadata(
        id: string,
        metadata: Record<string, unknown>,
        options: UpdateMetadataOptions = {}
    ): Promise<Session | null> {
        const { merge = true } = options;

        let updated: Session | undefined;

        if (merge) {
            [updated] = await db
                .update(schema.sessions)
                .set({
                    metadata: sql`${schema.sessions.metadata} || ${JSON.stringify(metadata)}::jsonb`,
                })
                .where(eq(schema.sessions.id, id))
                .returning();
        } else {
            [updated] = await db
                .update(schema.sessions)
                .set({ metadata })
                .where(eq(schema.sessions.id, id))
                .returning();
        }

        if (updated) {
            await _cacheSession(updated);
        }

        return updated ?? null;
    },

    /**
     * Extends the expiration time of a session.
     *
     * Use for sliding session expiration or explicit session extension
     * by the user.
     *
     * @param id - The UUID of the session
     * @param expiresAt - New expiration date
     * @returns The updated session, or null if not found
     *
     * @example
     * ```typescript
     * // Sliding expiration: extend session on activity
     * const newExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
     * await sessionsRepository.extendSession(session.id, newExpiry);
     *
     * // User-requested "remember me" extension
     * const thirtyDays = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
     * await sessionsRepository.extendSession(session.id, thirtyDays);
     * ```
     */
    async extendSession(id: string, expiresAt: Date): Promise<Session | null> {
        const [updated] = await db
            .update(schema.sessions)
            .set({ expiresAt })
            .where(
                and(
                    eq(schema.sessions.id, id),
                    isNull(schema.sessions.revokedAt)
                )
            )
            .returning();

        if (updated) {
            await _cacheSession(updated);
        }

        return updated ?? null;
    },

    // ========================================================================
    // REVOCATION OPERATIONS
    // ========================================================================

    /**
     * Revokes a session, making it permanently unusable.
     *
     * Revocation is a soft-delete operation that preserves the record for
     * audit purposes. Revoked sessions cannot be reactivated.
     *
     * @param id - The UUID of the session to revoke
     * @returns Revocation result with success status and session
     *
     * @example
     * ```typescript
     * // User logs out
     * const result = await sessionsRepository.revoke(session.id);
     *
     * if (result.success) {
     *   logger.info('Session revoked', {
     *     sessionId: result.session!.id,
     *     identityId: result.session!.identityId,
     *   });
     * }
     *
     * // Handle already revoked
     * if (result.error === 'already_revoked') {
     *   // Session was already revoked, no action needed
     * }
     * ```
     */
    async revoke(id: string): Promise<RevocationResult<Session>> {
        const existing = await this.findById(id);

        if (!existing) {
            return {
                success: false,
                data: null,
                message: "Session not found",
                error: 'SESSION_NOT_FOUND'
            };
        }

        if (existing.revokedAt) {
            return {
                success: false,
                data: existing,
                message: "Session already revoked",
                error: 'SESSION_ALREADY_REVOKED',
            };
        }

        const [revoked] = await db
            .update(schema.sessions)
            .set({ revokedAt: new Date() })
            .where(eq(schema.sessions.id, id))
            .returning();

        // Invalidate cache
        await _invalidateSessionCache(existing.sessionTokenHash);

        return { success: true, message: "Succes", data: revoked! };
    },

    /**
     * Revokes all sessions for an identity.
     *
     * Use when an account is compromised, during password change,
     * or when explicitly requested by the user ("sign out everywhere").
     *
     * @param identityId - The identity's UUID
     * @param excludeSessionId - Optional session ID to keep active (current session)
     * @returns Number of sessions revoked
     *
     * @example
     * ```typescript
     * // Sign out everywhere except current session
     * const revokedCount = await sessionsRepository.revokeAllByIdentityId(
     *   identity.id,
     *   currentSession.id
     * );
     *
     * logger.info('Signed out from all other devices', {
     *   identityId: identity.id,
     *   revokedSessions: revokedCount,
     * });
     *
     * // Password change: revoke ALL sessions
     * await sessionsRepository.revokeAllByIdentityId(identity.id);
     * ```
     *
     * @security
     * - Always revoke all sessions after password change
     * - Log this operation for security auditing
     * - Consider notifying user via email
     */
    async revokeAllByIdentityId(
        identityId: string,
        excludeSessionId?: string
    ): Promise<number> {
        const conditions: SQL[] = [
            eq(schema.sessions.identityId, identityId),
            isNull(schema.sessions.revokedAt),
        ];

        if (excludeSessionId) {
            conditions.push(sql`${schema.sessions.id} != ${excludeSessionId}`);
        }

        const result = await db
            .update(schema.sessions)
            .set({ revokedAt: new Date() })
            .where(and(...conditions))
            .returning({
                id: schema.sessions.id,
                sessionTokenHash: schema.sessions.sessionTokenHash,
            });

        // Invalidate all cached sessions
        await _invalidateIdentitySessions(identityId);

        return result.length;
    },

    /**
     * Revokes all sessions in a token family.
     *
     * CRITICAL for theft detection. When a refresh token is reused after
     * rotation, it indicates the token was stolen. Revoking the entire
     * family invalidates all potentially compromised sessions.
     *
     * @param tokenFamilyId - The token family UUID
     * @param reason - The revocation reason for audit trail
     * @returns Number of sessions revoked
     *
     * @example
     * ```typescript
     * // Refresh token reuse detected (THEFT!)
     * const revokedCount = await sessionsRepository.revokeByTokenFamilyId(
     *   tokenFamilyId,
     *   'stolen'
     * );
     *
     * logger.security('Token theft detected - family revoked', {
     *   tokenFamilyId,
     *   revokedSessions: revokedCount,
     *   reason: 'refresh_token_reuse',
     * });
     *
     * // Alert user through separate channel
     * await notificationService.sendSecurityAlert(identityId, {
     *   type: 'session_theft_detected',
     *   action: 'all_sessions_revoked',
     * });
     * ```
     *
     * @security
     * This is a critical security operation. Token reuse is a strong
     * indicator of theft and requires immediate action.
     */
    async revokeByTokenFamilyId(
        tokenFamilyId: string,
        reason: RevokedReason = 'family_revoked'
    ): Promise<number> {
        // Get sessions before revoking for cache invalidation
        const sessions = await db.query.sessions.findMany({
            where: and(
                eq(schema.sessions.tokenFamilyId, tokenFamilyId),
                isNull(schema.sessions.revokedAt)
            ),
            columns: {
                id: true,
                identityId: true,
                sessionTokenHash: true,
            },
        });

        if (sessions.length === 0) return 0;

        await db
            .update(schema.sessions)
            .set({ revokedAt: new Date() })
            .where(
                and(
                    eq(schema.sessions.tokenFamilyId, tokenFamilyId),
                    isNull(schema.sessions.revokedAt)
                )
            );

        // Invalidate all affected caches
        const identityIds = [...new Set(sessions.map((s) => s.identityId))];
        await Promise.all(
            identityIds.map((id) => _invalidateIdentitySessions(id))
        );

        return sessions.length;
    },

    /**
     * Revokes all sessions for an organization.
     *
     * Use during security incidents affecting the entire organization
     * or during organization deactivation.
     *
     * @param organizationId - The organization's UUID
     * @returns Number of sessions revoked
     *
     * @example
     * ```typescript
     * // Organization-wide security incident
     * const revokedCount = await sessionsRepository.revokeAllByOrganizationId(
     *   org.id
     * );
     *
     * logger.security('Organization-wide session revocation', {
     *   organizationId: org.id,
     *   revokedSessions: revokedCount,
     *   reason: 'security_incident',
     * });
     * ```
     *
     * @warning
     * This is a disruptive operation that will sign out ALL users
     * in the organization. Use only for serious security incidents.
     */
    async revokeAllByOrganizationId(organizationId: string): Promise<number> {
        // Get all affected identity IDs for cache invalidation
        const sessions = await db.query.sessions.findMany({
            where: and(
                eq(schema.sessions.organizationId, organizationId),
                isNull(schema.sessions.revokedAt)
            ),
            columns: { identityId: true },
        });

        if (sessions.length === 0) return 0;

        const result = await db
            .update(schema.sessions)
            .set({ revokedAt: new Date() })
            .where(
                and(
                    eq(schema.sessions.organizationId, organizationId),
                    isNull(schema.sessions.revokedAt)
                )
            )
            .returning({ id: schema.sessions.id });

        // Invalidate all affected caches
        const identityIds = [...new Set(sessions.map((s) => s.identityId))];
        await Promise.all(
            identityIds.map((id) => _invalidateIdentitySessions(id))
        );

        return result.length;
    },

    // ========================================================================
    // DELETE OPERATIONS
    // ========================================================================

    /**
     * Permanently deletes a session from the database.
     *
     * @param id - The UUID of the session to delete
     * @returns True if deleted, false if not found
     *
     * @example
     * ```typescript
     * // Hard delete during GDPR data erasure
     * const deleted = await sessionsRepository.deleteById(session.id);
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
        // Get session for cache invalidation
        const session = await this.findById(id);

        const result = await db
            .delete(schema.sessions)
            .where(eq(schema.sessions.id, id))
            .returning({ id: schema.sessions.id });

        if (session) {
            await _invalidateSessionCache(session.sessionTokenHash);
        }

        return result.length > 0;
    },

    /**
     * Deletes all revoked sessions older than a specified date.
     *
     * Use as part of a scheduled cleanup job to remove stale records
     * while maintaining recent audit history.
     *
     * @param olderThan - Delete records revoked before this date
     * @returns Number of records deleted
     *
     * @example
     * ```typescript
     * // Cleanup revoked sessions older than 30 days
     * const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
     * const deletedCount = await sessionsRepository.deleteRevokedBefore(
     *   thirtyDaysAgo
     * );
     *
     * logger.info('Cleaned up revoked sessions', { count: deletedCount });
     * ```
     */
    async deleteRevokedBefore(olderThan: Date): Promise<number> {
        const result = await db
            .delete(schema.sessions)
            .where(
                and(
                    lt(schema.sessions.revokedAt, olderThan),
                    sql`${schema.sessions.revokedAt} IS NOT NULL`
                )
            )
            .returning({ id: schema.sessions.id });

        return result.length;
    },

    /**
     * Deletes all expired sessions older than a specified date.
     *
     * Use as part of a scheduled cleanup job to remove expired sessions
     * that are no longer needed for audit purposes.
     *
     * @param olderThan - Delete sessions that expired before this date
     * @returns Number of records deleted
     *
     * @example
     * ```typescript
     * // Cleanup sessions expired more than 7 days ago
     * const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
     * const deletedCount = await sessionsRepository.deleteExpiredBefore(
     *   sevenDaysAgo
     * );
     * ```
     */
    async deleteExpiredBefore(olderThan: Date): Promise<number> {
        const result = await db
            .delete(schema.sessions)
            .where(lt(schema.sessions.expiresAt, olderThan))
            .returning({ id: schema.sessions.id });

        return result.length;
    },

    // ========================================================================
    // COUNT & STATISTICS
    // ========================================================================

    /**
     * Counts sessions for an identity with optional filtering.
     *
     * @param identityId - The identity's UUID
     * @param options - Filtering options
     * @returns Total count of matching sessions
     *
     * @example
     * ```typescript
     * // Count all sessions
     * const total = await sessionsRepository.countByIdentityId(identity.id);
     *
     * // Count only active sessions
     * const active = await sessionsRepository.countByIdentityId(identity.id, {
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

        const conditions: SQL[] = [eq(schema.sessions.identityId, identityId)];

        if (!includeRevoked) {
            conditions.push(isNull(schema.sessions.revokedAt));
        }

        if (!includeExpired) {
            const now = new Date();
            conditions.push(gt(schema.sessions.expiresAt, now));
        }

        const [result] = await db
            .select({ count: count() })
            .from(schema.sessions)
            .where(and(...conditions));

        return result?.count ?? 0;
    },

    /**
     * Gets comprehensive statistics about sessions for an identity.
     *
     * Provides counts broken down by status (active, revoked, expired)
     * for dashboard displays and security auditing.
     *
     * @param identityId - The identity's UUID
     * @returns Statistics object with counts by status
     *
     * @example
     * ```typescript
     * const stats = await sessionsRepository.getStatsByIdentityId(identity.id);
     *
     * console.log(`Total: ${stats.total}`);
     * console.log(`Active: ${stats.active}`);
     * console.log(`Revoked: ${stats.revoked}`);
     * console.log(`Expired: ${stats.expired}`);
     * ```
     */
    async getStatsByIdentityId(identityId: string): Promise<SessionStats> {
        const now = new Date();

        const [result] = await db
            .select({
                total: count(),
                revoked: count(schema.sessions.revokedAt),
                expired: sql<number>`COUNT(CASE
                    WHEN ${schema.sessions.expiresAt} < ${now}
                    AND ${schema.sessions.revokedAt} IS NULL
                    THEN 1
                END)`,
                active: sql<number>`COUNT(CASE
                    WHEN ${schema.sessions.revokedAt} IS NULL
                    AND ${schema.sessions.expiresAt} >= ${now}
                    THEN 1
                END)`,
            })
            .from(schema.sessions)
            .where(eq(schema.sessions.identityId, identityId));

        return {
            total: result?.total ?? 0,
            active: Number(result?.active ?? 0),
            revoked: result?.revoked ?? 0,
            expired: Number(result?.expired ?? 0),
        };
    },

    /**
     * Gets statistics about sessions for an organization.
     *
     * Useful for organization-wide security monitoring dashboards.
     *
     * @param organizationId - The organization's UUID
     * @returns Statistics object with counts by status
     *
     * @example
     * ```typescript
     * const stats = await sessionsRepository.getStatsByOrganizationId(org.id);
     *
     * // Display in admin dashboard
     * console.log(`Active sessions: ${stats.active}`);
     * console.log(`Revoked today: ${stats.revoked}`);
     * ```
     */
    async getStatsByOrganizationId(
        organizationId: string
    ): Promise<SessionStats> {
        const now = new Date();

        const [result] = await db
            .select({
                total: count(),
                revoked: count(schema.sessions.revokedAt),
                expired: sql<number>`COUNT(CASE
                    WHEN ${schema.sessions.expiresAt} < ${now}
                    AND ${schema.sessions.revokedAt} IS NULL
                    THEN 1
                END)`,
                active: sql<number>`COUNT(CASE
                    WHEN ${schema.sessions.revokedAt} IS NULL
                    AND ${schema.sessions.expiresAt} >= ${now}
                    THEN 1
                END)`,
            })
            .from(schema.sessions)
            .where(eq(schema.sessions.organizationId, organizationId));

        return {
            total: result?.total ?? 0,
            active: Number(result?.active ?? 0),
            revoked: result?.revoked ?? 0,
            expired: Number(result?.expired ?? 0),
        };
    },

    // ========================================================================
    // SECURITY & AUDIT
    // ========================================================================

    /**
     * Finds sessions that have been idle for a specified period.
     *
     * Use for security auditing to identify inactive sessions that
     * should be reviewed or automatically revoked.
     *
     * @param organizationId - The organization's UUID
     * @param idleSince - Find sessions not active since this date
     * @param options - Pagination options
     * @returns Paginated result of idle sessions
     *
     * @example
     * ```typescript
     * // Find sessions idle for more than 24 hours
     * const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
     * const idleSessions = await sessionsRepository.findIdleSince(
     *   org.id,
     *   oneDayAgo
     * );
     *
     * // Auto-revoke idle sessions
     * for (const session of idleSessions.data) {
     *   await sessionsRepository.revoke(session.id);
     * }
     * ```
     */
    async findIdleSince(
        organizationId: string,
        idleSince: Date,
        options: SessionPaginationOptions = {}
    ): Promise<PaginatedResult<Session>> {
        const { limit = 20, cursor } = options;
        const now = new Date();

        const conditions: SQL[] = [
            eq(schema.sessions.organizationId, organizationId),
            isNull(schema.sessions.revokedAt),
            gt(schema.sessions.expiresAt, now),
            lt(schema.sessions.lastActivityAt, idleSince),
        ];

        if (cursor) {
            const decoded = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.sessions, decoded, 'forward')
            );
        }

        const results = await db.query.sessions.findMany({
            where: and(...conditions),
            orderBy: [
                asc(schema.sessions.lastActivityAt),
                desc(schema.sessions.id),
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
     * Finds sessions expiring within a specified period.
     *
     * Use for proactive session management or to notify users
     * about expiring sessions.
     *
     * @param organizationId - The organization's UUID
     * @param withinMinutes - Number of minutes until expiration
     * @returns Array of sessions expiring soon
     *
     * @example
     * ```typescript
     * // Find sessions expiring in next 5 minutes
     * const expiringSessions = await sessionsRepository.findExpiringSoon(
     *   org.id,
     *   5
     * );
     *
     * // Send refresh token prompts
     * for (const session of expiringSessions) {
     *   await websocketService.sendToSession(session.id, {
     *     type: 'session_expiring',
     *     expiresAt: session.expiresAt,
     *   });
     * }
     * ```
     */
    async findExpiringSoon(
        organizationId: string,
        withinMinutes: number
    ): Promise<Session[]> {
        const now = new Date();
        const futureDate = new Date(now.getTime() + withinMinutes * 60 * 1000);

        return db.query.sessions.findMany({
            where: and(
                eq(schema.sessions.organizationId, organizationId),
                isNull(schema.sessions.revokedAt),
                gt(schema.sessions.expiresAt, now),
                lt(schema.sessions.expiresAt, futureDate)
            ),
            orderBy: [asc(schema.sessions.expiresAt)],
        });
    },

    /**
     * Counts unique IP addresses used by an identity in a time period.
     *
     * Useful for detecting account sharing or compromised credentials
     * being used from multiple locations.
     *
     * @param identityId - The identity's UUID
     * @param since - Count IPs used since this date
     * @returns Number of unique IP addresses
     *
     * @example
     * ```typescript
     * // Check for suspicious activity (many IPs in short time)
     * const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
     * const uniqueIps = await sessionsRepository.countUniqueIpsByIdentityId(
     *   identity.id,
     *   oneHourAgo
     * );
     *
     * if (uniqueIps > 5) {
     *   logger.security('Suspicious login pattern detected', {
     *     identityId: identity.id,
     *     uniqueIps,
     *     period: '1 hour',
     *   });
     * }
     * ```
     */
    async countUniqueIpsByIdentityId(
        identityId: string,
        since: Date
    ): Promise<number> {
        const [result] = await db
            .select({
                uniqueIps: sql<number>`COUNT(DISTINCT ${schema.sessions.ipAddress})`,
            })
            .from(schema.sessions)
            .where(
                and(
                    eq(schema.sessions.identityId, identityId),
                    gt(schema.sessions.createdAt, since)
                )
            );

        return Number(result?.uniqueIps ?? 0);
    },

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    /**
     * Invalidates all cached sessions.
     *
     * Use during maintenance or after bulk operations that may have
     * affected cached data.
     *
     * @returns Number of cache keys deleted
     *
     * @example
     * ```typescript
     * // After database maintenance
     * const cleared = await sessionsRepository.clearAllCache();
     * logger.info('Session cache cleared', { keysDeleted: cleared });
     * ```
     *
     * @warning
     * This will cause cache misses for all subsequent session lookups
     * until the cache is repopulated. Use sparingly.
     */
    async clearAllCache(): Promise<number> {
        const sessionKeys = await redis.keys(`${SESSION_CACHE_PREFIX}*`);
        const identityKeys = await redis.keys(`${IDENTITY_SESSIONS_PREFIX}*`);
        const allKeys = [...sessionKeys, ...identityKeys];

        if (allKeys.length === 0) return 0;

        await redis.del(...allKeys);
        return allKeys.length;
    },

    /**
     * Warms the cache with active sessions for an identity.
     *
     * Call after identity login or when expecting high session
     * validation traffic.
     *
     * @param identityId - The identity's UUID
     * @returns Number of sessions cached
     *
     * @example
     * ```typescript
     * // After successful login, pre-warm cache
     * await sessionsRepository.warmCacheForIdentity(identity.id);
     * ```
     */
    async warmCacheForIdentity(identityId: string): Promise<number> {
        const sessions = await this.findActiveByIdentityId(identityId);

        await Promise.all(sessions.map((session) => _cacheSession(session)));

        return sessions.length;
    },
};
