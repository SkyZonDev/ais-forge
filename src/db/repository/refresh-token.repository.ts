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
    RefreshToken,
    RefreshTokenInsert,
    RefreshTokenPaginationOptions,
    RefreshTokenStats,
} from '../../types/refresh-tokens';
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

/** Redis key prefix for refresh token cache */
const TOKEN_CACHE_PREFIX = 'refresh_token:';

/** Redis key prefix for identity's active tokens set */
const IDENTITY_TOKENS_PREFIX = 'identity:refresh_tokens:';

/** Redis key prefix for token family tracking */
const FAMILY_TOKENS_PREFIX = 'token_family:';

/** Default refresh token cache TTL in seconds (5 minutes) */
const TOKEN_CACHE_TTL = 300;

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/**
 * Generates the Redis cache key for a token hash.
 *
 * @param tokenHash - The refresh token hash
 * @returns Redis key string
 * @internal
 */
function _getTokenCacheKey(tokenHash: string): string {
    return `${TOKEN_CACHE_PREFIX}${tokenHash}`;
}

/**
 * Generates the Redis key for an identity's active tokens set.
 *
 * @param identityId - The identity's UUID
 * @returns Redis key string
 * @internal
 */
function _getIdentityTokensKey(identityId: string): string {
    return `${IDENTITY_TOKENS_PREFIX}${identityId}`;
}

/**
 * Generates the Redis key for a token family's active tokens set.
 *
 * @param tokenFamilyId - The token family's UUID
 * @returns Redis key string
 * @internal
 */
function _getTokenFamilyKey(tokenFamilyId: string): string {
    return `${FAMILY_TOKENS_PREFIX}${tokenFamilyId}`;
}

/**
 * Caches a refresh token in Redis for fast lookup.
 *
 * @param token - The refresh token to cache
 * @internal
 */
async function _cacheToken(token: RefreshToken): Promise<void> {
    const key = _getTokenCacheKey(token.tokenHash);
    const ttl = Math.min(
        TOKEN_CACHE_TTL,
        Math.floor((token.expiresAt.getTime() - Date.now()) / 1000)
    );

    if (ttl > 0) {
        await redis.setex(key, ttl, JSON.stringify(token));
    }
}

/**
 * Invalidates a refresh token from Redis cache.
 *
 * @param tokenHash - The token hash to invalidate
 * @internal
 */
async function _invalidateTokenCache(tokenHash: string): Promise<void> {
    await redis.del(_getTokenCacheKey(tokenHash));
}

/**
 * Invalidates all cached tokens for an identity.
 *
 * @param identityId - The identity's UUID
 * @internal
 */
async function _invalidateIdentityTokens(identityId: string): Promise<void> {
    const key = _getIdentityTokensKey(identityId);
    const tokenHashes = await redis.smembers(key);

    if (tokenHashes.length > 0) {
        const cacheKeys = tokenHashes.map((hash) => _getTokenCacheKey(hash));
        await redis.del(...cacheKeys, key);
    }
}

/**
 * Invalidates all cached tokens for a token family.
 *
 * @param tokenFamilyId - The token family's UUID
 * @internal
 */
async function _invalidateTokenFamily(tokenFamilyId: string): Promise<void> {
    const key = _getTokenFamilyKey(tokenFamilyId);
    const tokenHashes = await redis.smembers(key);

    if (tokenHashes.length > 0) {
        const cacheKeys = tokenHashes.map((hash) => _getTokenCacheKey(hash));
        await redis.del(...cacheKeys, key);
    }
}

/**
 * Adds a token to the identity and family tracking sets.
 *
 * @param token - The refresh token to track
 * @internal
 */
async function _trackToken(token: RefreshToken): Promise<void> {
    await Promise.all([
        redis.sadd(_getIdentityTokensKey(token.identityId), token.tokenHash),
        redis.sadd(_getTokenFamilyKey(token.tokenFamilyId), token.tokenHash),
    ]);
}

// ============================================================================
// REPOSITORY
// ============================================================================

export const refreshTokenRepository = {
    // ========================================================================
    // CREATE OPERATIONS
    // ========================================================================

    /**
     * Creates a new refresh token.
     *
     * Refresh tokens enable long-lived authentication by allowing clients to
     * obtain new access tokens without re-authentication. Each token belongs
     * to a token family for theft detection via rotation tracking.
     *
     * @param data - The refresh token data to insert
     * @returns The newly created refresh token record
     * @throws {Error} If insert fails (e.g., FK violation, duplicate hash, XOR constraint)
     *
     * @example
     * ```typescript
     * // Create refresh token for a session-based authentication
     * const plainToken = crypto.randomBytes(32).toString('base64url');
     * const tokenHash = await hashToken(plainToken);
     *
     * const refreshToken = await refreshTokenRepository.create({
     *   identityId: user.identityId,
     *   organizationId: user.organizationId,
     *   sessionId: session.id,
     *   tokenFamilyId: crypto.randomUUID(),
     *   tokenHash,
     *   expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
     * });
     *
     * // Return plain token to client (only time it's available)
     * return { refreshToken: plainToken };
     * ```
     *
     * @example
     * ```typescript
     * // Create refresh token for API key/PAT authentication
     * const refreshToken = await refreshTokenRepository.create({
     *   identityId: service.identityId,
     *   organizationId: service.organizationId,
     *   authMethodId: apiKey.id,
     *   tokenFamilyId: crypto.randomUUID(),
     *   tokenHash,
     *   expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days
     * });
     * ```
     *
     * @security
     * - NEVER store plain tokens, only hashed values
     * - Use cryptographically secure random tokens (min 256 bits)
     * - Ensure exactly one of sessionId or authMethodId is set (XOR constraint)
     * - Token families enable theft detection via rotation tracking
     */
    async create(data: RefreshTokenInsert): Promise<RefreshToken> {
        const [token] = await db
            .insert(schema.refreshTokens)
            .values(data)
            .returning();

        const created = token!;

        // Cache for fast lookup
        await _cacheToken(created);

        // Track in identity and family sets
        await _trackToken(created);

        return created;
    },

    /**
     * Creates multiple refresh tokens in a single transaction.
     *
     * Useful for batch operations like session migration or testing scenarios.
     *
     * @param data - Array of refresh token data to insert
     * @returns Array of newly created refresh token records
     * @throws {Error} If any insert fails (entire transaction is rolled back)
     *
     * @example
     * ```typescript
     * // Migrate tokens from legacy system
     * const tokens = await refreshTokenRepository.createMany(
     *   legacyTokens.map(legacy => ({
     *     identityId: userMapping[legacy.userId],
     *     organizationId: orgId,
     *     sessionId: sessionMapping[legacy.sessionId],
     *     tokenFamilyId: crypto.randomUUID(),
     *     tokenHash: legacy.tokenHash,
     *     expiresAt: legacy.expiry,
     *   }))
     * );
     * ```
     */
    async createMany(data: RefreshTokenInsert[]): Promise<RefreshToken[]> {
        if (data.length === 0) return [];

        const tokens = await db
            .insert(schema.refreshTokens)
            .values(data)
            .returning();

        // Cache and track all tokens
        await Promise.all(
            tokens.map(async (token) => {
                await _cacheToken(token);
                await _trackToken(token);
            })
        );

        return tokens;
    },

    // ========================================================================
    // READ OPERATIONS - Single Record
    // ========================================================================

    /**
     * Finds a refresh token by its unique identifier.
     *
     * @param id - The UUID of the refresh token
     * @returns The token if found, null otherwise
     *
     * @example
     * ```typescript
     * const token = await refreshTokenRepository.findById(tokenId);
     * if (!token) {
     *   throw new NotFoundError('Refresh token not found');
     * }
     * ```
     */
    async findById(id: string): Promise<RefreshToken | null> {
        const token = await db.query.refreshTokens.findFirst({
            where: eq(schema.refreshTokens.id, id),
        });

        return token ?? null;
    },

    /**
     * Finds an active (non-revoked, non-expired, unused) refresh token by ID.
     *
     * This is the preferred method when validating tokens for rotation.
     *
     * @param id - The UUID of the refresh token
     * @returns The active token if valid, null otherwise
     *
     * @example
     * ```typescript
     * const token = await refreshTokenRepository.findActiveById(tokenId);
     * if (!token) {
     *   throw new UnauthorizedError('Token invalid or expired');
     * }
     * ```
     */
    async findActiveById(id: string): Promise<RefreshToken | null> {
        const now = new Date();

        const token = await db.query.refreshTokens.findFirst({
            where: and(
                eq(schema.refreshTokens.id, id),
                isNull(schema.refreshTokens.revokedAt),
                isNull(schema.refreshTokens.usedAt),
                gt(schema.refreshTokens.expiresAt, now)
            ),
        });

        return token ?? null;
    },

    /**
     * Finds an active refresh token by its hash.
     *
     * This is the primary method for token validation during refresh flow.
     * Uses Redis caching for performance on high-traffic authentication.
     *
     * @param tokenHash - The SHA-256 hash of the refresh token
     * @returns The active token if valid, null otherwise
     *
     * @example
     * ```typescript
     * // Token refresh flow
     * async function refreshAccessToken(refreshTokenPlain: string): Promise<TokenPair> {
     *   const tokenHash = await hashToken(refreshTokenPlain);
     *   const token = await refreshTokenRepository.findActiveByTokenHash(tokenHash);
     *
     *   if (!token) {
     *     throw new UnauthorizedError('Invalid refresh token');
     *   }
     *
     *   // Check for token reuse (THEFT DETECTION!)
     *   if (token.usedAt) {
     *     await refreshTokenRepository.revokeByTokenFamilyId(
     *       token.tokenFamilyId,
     *       'stolen'
     *     );
     *     throw new SecurityError('Token reuse detected');
     *   }
     *
     *   // Rotate token
     *   const newTokenPair = await rotateToken(token);
     *   return newTokenPair;
     * }
     * ```
     *
     * @performance
     * This method uses Redis caching to minimize database load.
     * Cache hit ratio should be monitored in production.
     */
    async findActiveByTokenHash(
        tokenHash: string
    ): Promise<RefreshToken | null> {
        const now = new Date();

        // Try cache first
        const cached = await redis.get(_getTokenCacheKey(tokenHash));
        if (cached) {
            const token = JSON.parse(cached) as RefreshToken;

            // Parse date strings back to Date objects
            token.createdAt = new Date(token.createdAt);
            token.expiresAt = new Date(token.expiresAt);
            if (token.usedAt) token.usedAt = new Date(token.usedAt);
            if (token.revokedAt) token.revokedAt = new Date(token.revokedAt);

            // Validate cached token is still active
            if (!token.revokedAt && !token.usedAt && token.expiresAt > now) {
                return token;
            }

            // Cached token is no longer valid, remove from cache
            await _invalidateTokenCache(tokenHash);
        }

        // Cache miss or invalid - query database
        const token = await db.query.refreshTokens.findFirst({
            where: and(
                eq(schema.refreshTokens.tokenHash, tokenHash),
                isNull(schema.refreshTokens.revokedAt),
                isNull(schema.refreshTokens.usedAt),
                gt(schema.refreshTokens.expiresAt, now)
            ),
        });

        if (token) {
            await _cacheToken(token);
        }

        return token ?? null;
    },

    /**
     * Finds a token by hash regardless of status (for debugging/audit).
     *
     * Unlike findActiveByTokenHash, this returns tokens even if revoked,
     * used, or expired. Useful for investigating security incidents.
     *
     * @param tokenHash - The SHA-256 hash of the refresh token
     * @returns The token if found, null otherwise
     *
     * @example
     * ```typescript
     * // Investigate a potentially stolen token
     * const token = await refreshTokenRepository.findByTokenHash(suspiciousHash);
     * if (token?.revokedReason === 'stolen') {
     *   logger.security('Attempted use of known stolen token', {
     *     tokenId: token.id,
     *     identityId: token.identityId,
     *   });
     * }
     * ```
     */
    async findByTokenHash(tokenHash: string): Promise<RefreshToken | null> {
        const token = await db.query.refreshTokens.findFirst({
            where: eq(schema.refreshTokens.tokenHash, tokenHash),
        });

        return token ?? null;
    },

    // ========================================================================
    // READ OPERATIONS - Multiple Records
    // ========================================================================

    /**
     * Finds all refresh tokens for a specific identity with pagination.
     *
     * Results are ordered by creation date (newest first) and support
     * cursor-based pagination for efficient traversal.
     *
     * @param identityId - The identity's UUID
     * @param options - Pagination and filtering options
     * @returns Paginated result with tokens and navigation cursors
     *
     * @example
     * ```typescript
     * // Get active tokens for user's device management UI
     * const result = await refreshTokenRepository.findByIdentityId(identity.id, {
     *   limit: 10,
     *   includeUsed: false,
     * });
     *
     * // Display in security settings
     * result.data.forEach(token => {
     *   console.log(`Session: ${token.sessionId}`);
     *   console.log(`Created: ${token.createdAt}`);
     *   console.log(`Expires: ${token.expiresAt}`);
     * });
     * ```
     */
    async findByIdentityId(
        identityId: string,
        options: RefreshTokenPaginationOptions = {}
    ): Promise<PaginatedResult<RefreshToken>> {
        const {
            limit = 20,
            cursor,
            includeRevoked = false,
            includeUsed = false,
        } = options;

        const conditions: SQL[] = [
            eq(schema.refreshTokens.identityId, identityId),
        ];

        if (!includeRevoked) {
            conditions.push(isNull(schema.refreshTokens.revokedAt));
        }

        if (!includeUsed) {
            conditions.push(isNull(schema.refreshTokens.usedAt));
        }

        if (cursor) {
            const decoded = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.refreshTokens, decoded, 'forward')
            );
        }

        const results = await db.query.refreshTokens.findMany({
            where: and(...conditions),
            orderBy: [
                desc(schema.refreshTokens.createdAt),
                desc(schema.refreshTokens.id),
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
     * Finds all refresh tokens for a specific organization with pagination.
     *
     * Useful for organization administrators to audit token usage
     * across all identities.
     *
     * @param organizationId - The organization's UUID
     * @param options - Pagination and filtering options
     * @returns Paginated result with tokens and navigation cursors
     *
     * @example
     * ```typescript
     * // Security audit: count tokens per identity
     * const result = await refreshTokenRepository.findByOrganizationId(org.id, {
     *   limit: 100,
     * });
     *
     * const byIdentity = result.data.reduce((acc, t) => {
     *   acc[t.identityId] = (acc[t.identityId] || 0) + 1;
     *   return acc;
     * }, {} as Record<string, number>);
     * ```
     */
    async findByOrganizationId(
        organizationId: string,
        options: RefreshTokenPaginationOptions = {}
    ): Promise<PaginatedResult<RefreshToken>> {
        const {
            limit = 20,
            cursor,
            includeRevoked = false,
            includeUsed = false,
        } = options;

        const conditions: SQL[] = [
            eq(schema.refreshTokens.organizationId, organizationId),
        ];

        if (!includeRevoked) {
            conditions.push(isNull(schema.refreshTokens.revokedAt));
        }

        if (!includeUsed) {
            conditions.push(isNull(schema.refreshTokens.usedAt));
        }

        if (cursor) {
            const decoded = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.refreshTokens, decoded, 'forward')
            );
        }

        const results = await db.query.refreshTokens.findMany({
            where: and(...conditions),
            orderBy: [
                desc(schema.refreshTokens.createdAt),
                desc(schema.refreshTokens.id),
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
     * Finds all active (non-revoked, non-used, non-expired) tokens for an identity.
     *
     * Returns only currently valid tokens. Use for displaying active
     * authentication in user security settings.
     *
     * @param identityId - The identity's UUID
     * @returns Array of active tokens
     *
     * @example
     * ```typescript
     * // Display active devices/sessions
     * const activeTokens = await refreshTokenRepository.findActiveByIdentityId(
     *   identity.id
     * );
     *
     * // Group by session for display
     * const bySession = activeTokens.reduce((acc, t) => {
     *   if (t.sessionId) {
     *     acc[t.sessionId] = t;
     *   }
     *   return acc;
     * }, {} as Record<string, RefreshToken>);
     * ```
     */
    async findActiveByIdentityId(identityId: string): Promise<RefreshToken[]> {
        const now = new Date();

        return db.query.refreshTokens.findMany({
            where: and(
                eq(schema.refreshTokens.identityId, identityId),
                isNull(schema.refreshTokens.revokedAt),
                isNull(schema.refreshTokens.usedAt),
                gt(schema.refreshTokens.expiresAt, now)
            ),
            orderBy: [desc(schema.refreshTokens.createdAt)],
        });
    },

    /**
     * Finds all tokens in a token family.
     *
     * Token families track the lineage of rotated tokens. When theft is
     * detected (token reuse), the entire family should be revoked.
     *
     * @param tokenFamilyId - The token family UUID
     * @returns Array of tokens in the family
     *
     * @example
     * ```typescript
     * // Investigate token theft
     * const familyTokens = await refreshTokenRepository.findByTokenFamilyId(
     *   tokenFamilyId
     * );
     *
     * // Trace the token chain
     * const chain = familyTokens.sort((a, b) =>
     *   a.createdAt.getTime() - b.createdAt.getTime()
     * );
     *
     * logger.security('Token family audit', {
     *   tokenFamilyId,
     *   tokenCount: chain.length,
     *   firstToken: chain[0]?.id,
     *   lastToken: chain[chain.length - 1]?.id,
     * });
     * ```
     *
     * @security
     * Token family tracking is critical for detecting refresh token theft.
     * If a rotated token is reused, the entire family is compromised.
     */
    async findByTokenFamilyId(tokenFamilyId: string): Promise<RefreshToken[]> {
        return db.query.refreshTokens.findMany({
            where: eq(schema.refreshTokens.tokenFamilyId, tokenFamilyId),
            orderBy: [asc(schema.refreshTokens.createdAt)],
        });
    },

    /**
     * Finds all tokens associated with a specific session.
     *
     * @param sessionId - The session's UUID
     * @param options - Filtering options
     * @returns Array of tokens for the session
     *
     * @example
     * ```typescript
     * // Get token history for a session
     * const tokens = await refreshTokenRepository.findBySessionId(
     *   session.id,
     *   { includeUsed: true }
     * );
     *
     * // Check rotation count
     * console.log(`Session has rotated ${tokens.length} times`);
     * ```
     */
    async findBySessionId(
        sessionId: string,
        options: { includeRevoked?: boolean; includeUsed?: boolean } = {}
    ): Promise<RefreshToken[]> {
        const { includeRevoked = false, includeUsed = false } = options;

        const conditions: SQL[] = [
            eq(schema.refreshTokens.sessionId, sessionId),
        ];

        if (!includeRevoked) {
            conditions.push(isNull(schema.refreshTokens.revokedAt));
        }

        if (!includeUsed) {
            conditions.push(isNull(schema.refreshTokens.usedAt));
        }

        return db.query.refreshTokens.findMany({
            where: and(...conditions),
            orderBy: [desc(schema.refreshTokens.createdAt)],
        });
    },

    /**
     * Finds the currently active token for a session.
     *
     * Each session should have at most one active refresh token at any time.
     *
     * @param sessionId - The session's UUID
     * @returns The active token if exists, null otherwise
     *
     * @example
     * ```typescript
     * // Check if session has valid refresh token
     * const activeToken = await refreshTokenRepository.findActiveBySessionId(
     *   session.id
     * );
     *
     * if (!activeToken) {
     *   // Session needs re-authentication
     *   throw new UnauthorizedError('Session expired');
     * }
     * ```
     */
    async findActiveBySessionId(
        sessionId: string
    ): Promise<RefreshToken | null> {
        const now = new Date();

        const token = await db.query.refreshTokens.findFirst({
            where: and(
                eq(schema.refreshTokens.sessionId, sessionId),
                isNull(schema.refreshTokens.revokedAt),
                isNull(schema.refreshTokens.usedAt),
                gt(schema.refreshTokens.expiresAt, now)
            ),
            orderBy: [desc(schema.refreshTokens.createdAt)],
        });

        return token ?? null;
    },

    /**
     * Finds all tokens associated with a specific auth method.
     *
     * Auth methods (PATs, API keys) can have their own refresh tokens
     * for long-lived programmatic access.
     *
     * @param authMethodId - The auth method's UUID
     * @param options - Filtering options
     * @returns Array of tokens for the auth method
     *
     * @example
     * ```typescript
     * // Audit API key usage
     * const tokens = await refreshTokenRepository.findByAuthMethodId(
     *   apiKey.id,
     *   { includeUsed: true, includeRevoked: true }
     * );
     *
     * console.log(`API key has ${tokens.length} token records`);
     * ```
     */
    async findByAuthMethodId(
        authMethodId: string,
        options: { includeRevoked?: boolean; includeUsed?: boolean } = {}
    ): Promise<RefreshToken[]> {
        const { includeRevoked = false, includeUsed = false } = options;

        const conditions: SQL[] = [
            eq(schema.refreshTokens.authMethodId, authMethodId),
        ];

        if (!includeRevoked) {
            conditions.push(isNull(schema.refreshTokens.revokedAt));
        }

        if (!includeUsed) {
            conditions.push(isNull(schema.refreshTokens.usedAt));
        }

        return db.query.refreshTokens.findMany({
            where: and(...conditions),
            orderBy: [desc(schema.refreshTokens.createdAt)],
        });
    },

    /**
     * Finds the currently active token for an auth method.
     *
     * @param authMethodId - The auth method's UUID
     * @returns The active token if exists, null otherwise
     */
    async findActiveByAuthMethodId(
        authMethodId: string
    ): Promise<RefreshToken | null> {
        const now = new Date();

        const token = await db.query.refreshTokens.findFirst({
            where: and(
                eq(schema.refreshTokens.authMethodId, authMethodId),
                isNull(schema.refreshTokens.revokedAt),
                isNull(schema.refreshTokens.usedAt),
                gt(schema.refreshTokens.expiresAt, now)
            ),
            orderBy: [desc(schema.refreshTokens.createdAt)],
        });

        return token ?? null;
    },

    /**
     * Finds the parent token in the rotation chain.
     *
     * Useful for tracing token lineage during security investigations.
     *
     * @param id - The UUID of the token
     * @returns The parent token if exists, null otherwise
     *
     * @example
     * ```typescript
     * // Trace token ancestry
     * let current = suspiciousToken;
     * const chain: RefreshToken[] = [current];
     *
     * while (current.parentTokenId) {
     *   const parent = await refreshTokenRepository.findParent(current.id);
     *   if (!parent) break;
     *   chain.unshift(parent);
     *   current = parent;
     * }
     *
     * console.log(`Token chain depth: ${chain.length}`);
     * ```
     */
    async findParent(id: string): Promise<RefreshToken | null> {
        const token = await this.findById(id);
        if (!token?.parentTokenId) return null;

        return this.findById(token.parentTokenId);
    },

    /**
     * Finds child tokens (tokens rotated from this one).
     *
     * @param id - The UUID of the parent token
     * @returns Array of child tokens
     *
     * @example
     * ```typescript
     * // Check if token was already rotated
     * const children = await refreshTokenRepository.findChildren(token.id);
     * if (children.length > 0) {
     *   // This token has been used and rotated
     *   logger.security('Attempted reuse of rotated token', {
     *     originalTokenId: token.id,
     *     rotatedToId: children[0].id,
     *   });
     * }
     * ```
     */
    async findChildren(id: string): Promise<RefreshToken[]> {
        return db.query.refreshTokens.findMany({
            where: eq(schema.refreshTokens.parentTokenId, id),
            orderBy: [asc(schema.refreshTokens.createdAt)],
        });
    },

    // ========================================================================
    // UPDATE OPERATIONS
    // ========================================================================

    /**
     * Marks a token as used during rotation.
     *
     * This is CRITICAL for theft detection. When a token is rotated, the old
     * token is marked as used. If anyone attempts to use it again, we know
     * the token was stolen (either the legitimate user or attacker has it).
     *
     * @param id - The UUID of the token
     * @param reason - The revocation reason (typically 'used')
     * @returns The updated token, or null if not found
     *
     * @example
     * ```typescript
     * // Token rotation flow
     * async function rotateToken(oldToken: RefreshToken): Promise<RefreshToken> {
     *   // Create new token with same family
     *   const newToken = await refreshTokenRepository.create({
     *     identityId: oldToken.identityId,
     *     organizationId: oldToken.organizationId,
     *     sessionId: oldToken.sessionId,
     *     tokenFamilyId: oldToken.tokenFamilyId, // Same family!
     *     parentTokenId: oldToken.id,
     *     tokenHash: await hashToken(newPlainToken),
     *     expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
     *   });
     *
     *   // Mark old token as used
     *   await refreshTokenRepository.markAsUsed(oldToken.id, 'used');
     *
     *   return newToken;
     * }
     * ```
     *
     * @security
     * This operation is fundamental to refresh token security:
     * 1. Marks token as consumed (cannot be reused)
     * 2. Preserves audit trail via revokedReason
     * 3. Enables theft detection on reuse attempts
     */
    async markAsUsed(
        id: string,
        reason: RevokedReason = 'used'
    ): Promise<RefreshToken | null> {
        const now = new Date();

        const [updated] = await db
            .update(schema.refreshTokens)
            .set({
                usedAt: now,
                revokedAt: now,
                revokedReason: reason,
            })
            .where(
                and(
                    eq(schema.refreshTokens.id, id),
                    isNull(schema.refreshTokens.usedAt),
                    isNull(schema.refreshTokens.revokedAt)
                )
            )
            .returning();

        if (updated) {
            await _invalidateTokenCache(updated.tokenHash);
        }

        return updated ?? null;
    },

    // ========================================================================
    // REVOCATION OPERATIONS
    // ========================================================================

    /**
     * Revokes a refresh token, making it permanently unusable.
     *
     * Revocation is a soft-delete operation that preserves the record for
     * audit purposes. Revoked tokens cannot be reactivated.
     *
     * @param id - The UUID of the token to revoke
     * @param reason - The reason for revocation
     * @returns Revocation result with success status and token
     *
     * @example
     * ```typescript
     * // Manual revocation by user
     * const result = await refreshTokenRepository.revoke(tokenId, 'manual');
     *
     * if (result.success) {
     *   logger.info('Token revoked', {
     *     tokenId: result.data!.id,
     *     reason: 'manual',
     *   });
     * }
     * ```
     */
    async revoke(
        id: string,
        reason: RevokedReason = 'manual'
    ): Promise<RevocationResult<RefreshToken>> {
        const existing = await this.findById(id);

        if (!existing) {
            return {
                success: false,
                data: null,
                message: 'Refresh token not found',
                error: 'REFRESH_TOKEN_NOT_FOUND',
            };
        }

        if (existing.revokedAt) {
            return {
                success: false,
                data: existing,
                message: 'Refresh token already revoked',
                error: 'REFRESH_TOKEN_ALREADY_REVOKED',
            };
        }

        const [revoked] = await db
            .update(schema.refreshTokens)
            .set({
                revokedAt: new Date(),
                revokedReason: reason,
            })
            .where(eq(schema.refreshTokens.id, id))
            .returning();

        // Invalidate cache
        await _invalidateTokenCache(existing.tokenHash);

        return { success: true, message: 'Success', data: revoked! };
    },

    /**
     * Revokes all tokens for an identity.
     *
     * Use when an account is compromised, during password change,
     * or when explicitly requested by the user.
     *
     * @param identityId - The identity's UUID
     * @param reason - The revocation reason
     * @param excludeTokenId - Optional token ID to keep active
     * @returns Number of tokens revoked
     *
     * @example
     * ```typescript
     * // Password change: revoke all tokens
     * const revokedCount = await refreshTokenRepository.revokeAllByIdentityId(
     *   identity.id,
     *   'manual'
     * );
     *
     * logger.security('All tokens revoked on password change', {
     *   identityId: identity.id,
     *   revokedCount,
     * });
     * ```
     *
     * @security
     * - Always revoke all tokens after password change
     * - Log this operation for security auditing
     */
    async revokeAllByIdentityId(
        identityId: string,
        reason: RevokedReason = 'manual',
        excludeTokenId?: string
    ): Promise<number> {
        const conditions: SQL[] = [
            eq(schema.refreshTokens.identityId, identityId),
            isNull(schema.refreshTokens.revokedAt),
        ];

        if (excludeTokenId) {
            conditions.push(
                sql`${schema.refreshTokens.id} != ${excludeTokenId}`
            );
        }

        const result = await db
            .update(schema.refreshTokens)
            .set({
                revokedAt: new Date(),
                revokedReason: reason,
            })
            .where(and(...conditions))
            .returning({ id: schema.refreshTokens.id });

        // Invalidate all cached tokens
        await _invalidateIdentityTokens(identityId);

        return result.length;
    },

    /**
     * Revokes all tokens in a token family.
     *
     * CRITICAL for theft detection. When a refresh token is reused after
     * rotation, it indicates the token was stolen. Revoking the entire
     * family invalidates all potentially compromised tokens.
     *
     * @param tokenFamilyId - The token family UUID
     * @param reason - The revocation reason (typically 'stolen')
     * @returns Number of tokens revoked
     *
     * @example
     * ```typescript
     * // Token reuse detected (THEFT!)
     * async function handleTokenReuse(token: RefreshToken): Promise<void> {
     *   // Revoke entire token family
     *   const revokedCount = await refreshTokenRepository.revokeByTokenFamilyId(
     *     token.tokenFamilyId,
     *     'stolen'
     *   );
     *
     *   logger.security('Token theft detected - family revoked', {
     *     tokenFamilyId: token.tokenFamilyId,
     *     identityId: token.identityId,
     *     revokedCount,
     *     originalTokenId: token.id,
     *   });
     *
     *   // Notify user through separate channel
     *   await notificationService.sendSecurityAlert(token.identityId, {
     *     type: 'token_theft_detected',
     *     action: 'all_sessions_revoked',
     *   });
     * }
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
        // Get tokens before revoking for cache invalidation
        const tokens = await db.query.refreshTokens.findMany({
            where: and(
                eq(schema.refreshTokens.tokenFamilyId, tokenFamilyId),
                isNull(schema.refreshTokens.revokedAt)
            ),
            columns: {
                id: true,
                identityId: true,
                tokenHash: true,
            },
        });

        if (tokens.length === 0) return 0;

        await db
            .update(schema.refreshTokens)
            .set({
                revokedAt: new Date(),
                revokedReason: reason,
            })
            .where(
                and(
                    eq(schema.refreshTokens.tokenFamilyId, tokenFamilyId),
                    isNull(schema.refreshTokens.revokedAt)
                )
            );

        // Invalidate all affected caches
        await _invalidateTokenFamily(tokenFamilyId);
        const identityIds = [...new Set(tokens.map((t) => t.identityId))];
        await Promise.all(
            identityIds.map((id) => _invalidateIdentityTokens(id))
        );

        return tokens.length;
    },

    /**
     * Revokes all tokens for a specific session.
     *
     * Use when a session is terminated or compromised.
     *
     * @param sessionId - The session's UUID
     * @param reason - The revocation reason
     * @returns Number of tokens revoked
     *
     * @example
     * ```typescript
     * // User logs out from a session
     * await refreshTokenRepository.revokeBySessionId(session.id, 'logout');
     * ```
     */
    async revokeBySessionId(
        sessionId: string,
        reason: RevokedReason = 'logout'
    ): Promise<number> {
        const tokens = await db.query.refreshTokens.findMany({
            where: and(
                eq(schema.refreshTokens.sessionId, sessionId),
                isNull(schema.refreshTokens.revokedAt)
            ),
            columns: {
                id: true,
                identityId: true,
                tokenHash: true,
                tokenFamilyId: true,
            },
        });

        if (tokens.length === 0) return 0;

        await db
            .update(schema.refreshTokens)
            .set({
                revokedAt: new Date(),
                revokedReason: reason,
            })
            .where(
                and(
                    eq(schema.refreshTokens.sessionId, sessionId),
                    isNull(schema.refreshTokens.revokedAt)
                )
            );

        // Invalidate caches
        const identityIds = [...new Set(tokens.map((t) => t.identityId))];
        const familyIds = [...new Set(tokens.map((t) => t.tokenFamilyId))];

        await Promise.all([
            ...identityIds.map((id) => _invalidateIdentityTokens(id)),
            ...familyIds.map((id) => _invalidateTokenFamily(id)),
        ]);

        return tokens.length;
    },

    /**
     * Revokes all tokens for an auth method.
     *
     * Use when an API key or PAT is revoked or compromised.
     *
     * @param authMethodId - The auth method's UUID
     * @param reason - The revocation reason
     * @returns Number of tokens revoked
     *
     * @example
     * ```typescript
     * // API key revoked by admin
     * await refreshTokenRepository.revokeByAuthMethodId(apiKey.id, 'manual');
     * ```
     */
    async revokeByAuthMethodId(
        authMethodId: string,
        reason: RevokedReason = 'manual'
    ): Promise<number> {
        const tokens = await db.query.refreshTokens.findMany({
            where: and(
                eq(schema.refreshTokens.authMethodId, authMethodId),
                isNull(schema.refreshTokens.revokedAt)
            ),
            columns: {
                id: true,
                identityId: true,
                tokenHash: true,
                tokenFamilyId: true,
            },
        });

        if (tokens.length === 0) return 0;

        await db
            .update(schema.refreshTokens)
            .set({
                revokedAt: new Date(),
                revokedReason: reason,
            })
            .where(
                and(
                    eq(schema.refreshTokens.authMethodId, authMethodId),
                    isNull(schema.refreshTokens.revokedAt)
                )
            );

        // Invalidate caches
        const identityIds = [...new Set(tokens.map((t) => t.identityId))];
        const familyIds = [...new Set(tokens.map((t) => t.tokenFamilyId))];

        await Promise.all([
            ...identityIds.map((id) => _invalidateIdentityTokens(id)),
            ...familyIds.map((id) => _invalidateTokenFamily(id)),
        ]);

        return tokens.length;
    },

    /**
     * Revokes all tokens for an organization.
     *
     * Use during security incidents affecting the entire organization.
     *
     * @param organizationId - The organization's UUID
     * @param reason - The revocation reason
     * @returns Number of tokens revoked
     *
     * @warning
     * This is a disruptive operation that will invalidate ALL tokens
     * in the organization. Use only for serious security incidents.
     */
    async revokeAllByOrganizationId(
        organizationId: string,
        reason: RevokedReason = 'manual'
    ): Promise<number> {
        // Get all affected identity IDs for cache invalidation
        const tokens = await db.query.refreshTokens.findMany({
            where: and(
                eq(schema.refreshTokens.organizationId, organizationId),
                isNull(schema.refreshTokens.revokedAt)
            ),
            columns: {
                identityId: true,
                tokenFamilyId: true,
            },
        });

        if (tokens.length === 0) return 0;

        const result = await db
            .update(schema.refreshTokens)
            .set({
                revokedAt: new Date(),
                revokedReason: reason,
            })
            .where(
                and(
                    eq(schema.refreshTokens.organizationId, organizationId),
                    isNull(schema.refreshTokens.revokedAt)
                )
            )
            .returning({ id: schema.refreshTokens.id });

        // Invalidate all affected caches
        const identityIds = [...new Set(tokens.map((t) => t.identityId))];
        const familyIds = [...new Set(tokens.map((t) => t.tokenFamilyId))];

        await Promise.all([
            ...identityIds.map((id) => _invalidateIdentityTokens(id)),
            ...familyIds.map((id) => _invalidateTokenFamily(id)),
        ]);

        return result.length;
    },

    // ========================================================================
    // DELETE OPERATIONS
    // ========================================================================

    /**
     * Permanently deletes a refresh token from the database.
     *
     * @param id - The UUID of the token to delete
     * @returns True if deleted, false if not found
     *
     * @warning
     * This is a hard delete operation. Consider using `revoke()` instead
     * to preserve audit trails. Use only for:
     * - GDPR/CCPA data erasure requests
     * - Cleanup of test data
     * - Regulatory compliance requirements
     */
    async deleteById(id: string): Promise<boolean> {
        // Get token for cache invalidation
        const token = await this.findById(id);

        const result = await db
            .delete(schema.refreshTokens)
            .where(eq(schema.refreshTokens.id, id))
            .returning({ id: schema.refreshTokens.id });

        if (token) {
            await _invalidateTokenCache(token.tokenHash);
        }

        return result.length > 0;
    },

    /**
     * Deletes all revoked tokens older than a specified date.
     *
     * Use as part of a scheduled cleanup job to remove stale records
     * while maintaining recent audit history.
     *
     * @param olderThan - Delete records revoked before this date
     * @returns Number of records deleted
     *
     * @example
     * ```typescript
     * // Cleanup revoked tokens older than 30 days
     * const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
     * const deletedCount = await refreshTokenRepository.deleteRevokedBefore(
     *   thirtyDaysAgo
     * );
     *
     * logger.info('Cleaned up revoked tokens', { count: deletedCount });
     * ```
     */
    async deleteRevokedBefore(olderThan: Date): Promise<number> {
        const result = await db
            .delete(schema.refreshTokens)
            .where(
                and(
                    lt(schema.refreshTokens.revokedAt, olderThan),
                    sql`${schema.refreshTokens.revokedAt} IS NOT NULL`
                )
            )
            .returning({ id: schema.refreshTokens.id });

        return result.length;
    },

    /**
     * Deletes all expired tokens older than a specified date.
     *
     * Use as part of a scheduled cleanup job to remove expired tokens
     * that are no longer needed for audit purposes.
     *
     * @param olderThan - Delete tokens that expired before this date
     * @returns Number of records deleted
     *
     * @example
     * ```typescript
     * // Cleanup tokens expired more than 7 days ago
     * const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
     * const deletedCount = await refreshTokenRepository.deleteExpiredBefore(
     *   sevenDaysAgo
     * );
     * ```
     */
    async deleteExpiredBefore(olderThan: Date): Promise<number> {
        const result = await db
            .delete(schema.refreshTokens)
            .where(lt(schema.refreshTokens.expiresAt, olderThan))
            .returning({ id: schema.refreshTokens.id });

        return result.length;
    },

    /**
     * Deletes all used tokens older than a specified date.
     *
     * Used tokens have been consumed during rotation and are kept
     * for theft detection. Cleanup old ones to save storage.
     *
     * @param olderThan - Delete tokens used before this date
     * @returns Number of records deleted
     *
     * @example
     * ```typescript
     * // Cleanup used tokens older than 90 days
     * const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
     * const deletedCount = await refreshTokenRepository.deleteUsedBefore(
     *   ninetyDaysAgo
     * );
     * ```
     */
    async deleteUsedBefore(olderThan: Date): Promise<number> {
        const result = await db
            .delete(schema.refreshTokens)
            .where(
                and(
                    lt(schema.refreshTokens.usedAt, olderThan),
                    sql`${schema.refreshTokens.usedAt} IS NOT NULL`
                )
            )
            .returning({ id: schema.refreshTokens.id });

        return result.length;
    },

    // ========================================================================
    // COUNT & STATISTICS
    // ========================================================================

    /**
     * Counts tokens for an identity with optional filtering.
     *
     * @param identityId - The identity's UUID
     * @param options - Filtering options
     * @returns Total count of matching tokens
     *
     * @example
     * ```typescript
     * // Count active tokens only
     * const active = await refreshTokenRepository.countByIdentityId(identity.id, {
     *   includeRevoked: false,
     *   includeUsed: false,
     *   includeExpired: false,
     * });
     * ```
     */
    async countByIdentityId(
        identityId: string,
        options: {
            includeRevoked?: boolean;
            includeUsed?: boolean;
            includeExpired?: boolean;
        } = {}
    ): Promise<number> {
        const {
            includeRevoked = true,
            includeUsed = true,
            includeExpired = true,
        } = options;

        const conditions: SQL[] = [
            eq(schema.refreshTokens.identityId, identityId),
        ];

        if (!includeRevoked) {
            conditions.push(isNull(schema.refreshTokens.revokedAt));
        }

        if (!includeUsed) {
            conditions.push(isNull(schema.refreshTokens.usedAt));
        }

        if (!includeExpired) {
            const now = new Date();
            conditions.push(gt(schema.refreshTokens.expiresAt, now));
        }

        const [result] = await db
            .select({ count: count() })
            .from(schema.refreshTokens)
            .where(and(...conditions));

        return result?.count ?? 0;
    },

    /**
     * Gets comprehensive statistics about refresh tokens for an identity.
     *
     * @param identityId - The identity's UUID
     * @returns Statistics object with counts by status
     *
     * @example
     * ```typescript
     * const stats = await refreshTokenRepository.getStatsByIdentityId(identity.id);
     *
     * console.log(`Total: ${stats.total}`);
     * console.log(`Active: ${stats.active}`);
     * console.log(`Used (rotated): ${stats.used}`);
     * console.log(`Revoked: ${stats.revoked}`);
     * console.log(`Expired: ${stats.expired}`);
     * ```
     */
    async getStatsByIdentityId(identityId: string): Promise<RefreshTokenStats> {
        const now = new Date();

        const [result] = await db
            .select({
                total: count(),
                revoked: sql<number>`COUNT(CASE
                    WHEN ${schema.refreshTokens.revokedAt} IS NOT NULL
                    AND ${schema.refreshTokens.usedAt} IS NULL
                    THEN 1
                END)`,
                used: sql<number>`COUNT(CASE
                    WHEN ${schema.refreshTokens.usedAt} IS NOT NULL
                    THEN 1
                END)`,
                expired: sql<number>`COUNT(CASE
                    WHEN ${schema.refreshTokens.expiresAt} < ${now}
                    AND ${schema.refreshTokens.revokedAt} IS NULL
                    AND ${schema.refreshTokens.usedAt} IS NULL
                    THEN 1
                END)`,
                active: sql<number>`COUNT(CASE
                    WHEN ${schema.refreshTokens.revokedAt} IS NULL
                    AND ${schema.refreshTokens.usedAt} IS NULL
                    AND ${schema.refreshTokens.expiresAt} >= ${now}
                    THEN 1
                END)`,
                stolen: sql<number>`COUNT(CASE
                    WHEN ${schema.refreshTokens.revokedReason} = 'stolen'
                    THEN 1
                END)`,
            })
            .from(schema.refreshTokens)
            .where(eq(schema.refreshTokens.identityId, identityId));

        return {
            total: result?.total ?? 0,
            active: Number(result?.active ?? 0),
            used: Number(result?.used ?? 0),
            revoked: Number(result?.revoked ?? 0),
            expired: Number(result?.expired ?? 0),
            stolen: Number(result?.stolen ?? 0),
        };
    },

    /**
     * Gets statistics about refresh tokens for an organization.
     *
     * @param organizationId - The organization's UUID
     * @returns Statistics object with counts by status
     *
     * @example
     * ```typescript
     * const stats = await refreshTokenRepository.getStatsByOrganizationId(org.id);
     *
     * // Alert on high theft count
     * if (stats.stolen > 0) {
     *   logger.security('Stolen tokens detected in organization', {
     *     organizationId: org.id,
     *     stolenCount: stats.stolen,
     *   });
     * }
     * ```
     */
    async getStatsByOrganizationId(
        organizationId: string
    ): Promise<RefreshTokenStats> {
        const now = new Date();

        const [result] = await db
            .select({
                total: count(),
                revoked: sql<number>`COUNT(CASE
                    WHEN ${schema.refreshTokens.revokedAt} IS NOT NULL
                    AND ${schema.refreshTokens.usedAt} IS NULL
                    THEN 1
                END)`,
                used: sql<number>`COUNT(CASE
                    WHEN ${schema.refreshTokens.usedAt} IS NOT NULL
                    THEN 1
                END)`,
                expired: sql<number>`COUNT(CASE
                    WHEN ${schema.refreshTokens.expiresAt} < ${now}
                    AND ${schema.refreshTokens.revokedAt} IS NULL
                    AND ${schema.refreshTokens.usedAt} IS NULL
                    THEN 1
                END)`,
                active: sql<number>`COUNT(CASE
                    WHEN ${schema.refreshTokens.revokedAt} IS NULL
                    AND ${schema.refreshTokens.usedAt} IS NULL
                    AND ${schema.refreshTokens.expiresAt} >= ${now}
                    THEN 1
                END)`,
                stolen: sql<number>`COUNT(CASE
                    WHEN ${schema.refreshTokens.revokedReason} = 'stolen'
                    THEN 1
                END)`,
            })
            .from(schema.refreshTokens)
            .where(eq(schema.refreshTokens.organizationId, organizationId));

        return {
            total: result?.total ?? 0,
            active: Number(result?.active ?? 0),
            used: Number(result?.used ?? 0),
            revoked: Number(result?.revoked ?? 0),
            expired: Number(result?.expired ?? 0),
            stolen: Number(result?.stolen ?? 0),
        };
    },

    // ========================================================================
    // SECURITY & AUDIT
    // ========================================================================

    /**
     * Finds tokens expiring within a specified period.
     *
     * Use for proactive token refresh or to notify users about
     * expiring authentication.
     *
     * @param organizationId - The organization's UUID
     * @param withinMinutes - Number of minutes until expiration
     * @returns Array of tokens expiring soon
     *
     * @example
     * ```typescript
     * // Find tokens expiring in next 5 minutes
     * const expiringTokens = await refreshTokenRepository.findExpiringSoon(
     *   org.id,
     *   5
     * );
     *
     * // Trigger proactive refresh for connected clients
     * for (const token of expiringTokens) {
     *   await websocketService.sendToIdentity(token.identityId, {
     *     type: 'token_expiring',
     *     sessionId: token.sessionId,
     *   });
     * }
     * ```
     */
    async findExpiringSoon(
        organizationId: string,
        withinMinutes: number
    ): Promise<RefreshToken[]> {
        const now = new Date();
        const futureDate = new Date(now.getTime() + withinMinutes * 60 * 1000);

        return db.query.refreshTokens.findMany({
            where: and(
                eq(schema.refreshTokens.organizationId, organizationId),
                isNull(schema.refreshTokens.revokedAt),
                isNull(schema.refreshTokens.usedAt),
                gt(schema.refreshTokens.expiresAt, now),
                lt(schema.refreshTokens.expiresAt, futureDate)
            ),
            orderBy: [asc(schema.refreshTokens.expiresAt)],
        });
    },

    /**
     * Counts tokens by revocation reason for security analysis.
     *
     * Useful for identifying patterns in token revocation and
     * detecting security incidents.
     *
     * @param organizationId - The organization's UUID
     * @param since - Count revocations since this date
     * @returns Object with counts per revocation reason
     *
     * @example
     * ```typescript
     * // Weekly security report
     * const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
     * const revocationStats = await refreshTokenRepository.countByRevocationReason(
     *   org.id,
     *   oneWeekAgo
     * );
     *
     * console.log(`Stolen tokens this week: ${revocationStats.stolen}`);
     * console.log(`Manual revocations: ${revocationStats.manual}`);
     * console.log(`Normal rotations: ${revocationStats.used}`);
     * ```
     */
    async countByRevocationReason(
        organizationId: string,
        since: Date
    ): Promise<Record<RevokedReason, number>> {
        const result = await db
            .select({
                reason: schema.refreshTokens.revokedReason,
                count: count(),
            })
            .from(schema.refreshTokens)
            .where(
                and(
                    eq(schema.refreshTokens.organizationId, organizationId),
                    gt(schema.refreshTokens.revokedAt, since),
                    sql`${schema.refreshTokens.revokedReason} IS NOT NULL`
                )
            )
            .groupBy(schema.refreshTokens.revokedReason);

        // Initialize all reasons to 0
        const stats: Record<RevokedReason, number> = {
            used: 0,
            stolen: 0,
            manual: 0,
            family_revoked: 0,
            expired: 0,
            logout: 0,
        };

        // Fill in actual counts
        for (const row of result) {
            if (row.reason) {
                stats[row.reason] = row.count;
            }
        }

        return stats;
    },

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    /**
     * Invalidates all cached refresh tokens.
     *
     * Use during maintenance or after bulk operations that may have
     * affected cached data.
     *
     * @returns Number of cache keys deleted
     *
     * @warning
     * This will cause cache misses for all subsequent token lookups
     * until the cache is repopulated. Use sparingly.
     */
    async clearAllCache(): Promise<number> {
        const tokenKeys = await redis.keys(`${TOKEN_CACHE_PREFIX}*`);
        const identityKeys = await redis.keys(`${IDENTITY_TOKENS_PREFIX}*`);
        const familyKeys = await redis.keys(`${FAMILY_TOKENS_PREFIX}*`);
        const allKeys = [...tokenKeys, ...identityKeys, ...familyKeys];

        if (allKeys.length === 0) return 0;

        await redis.del(...allKeys);
        return allKeys.length;
    },

    /**
     * Warms the cache with active tokens for an identity.
     *
     * Call after identity login or when expecting high token
     * validation traffic.
     *
     * @param identityId - The identity's UUID
     * @returns Number of tokens cached
     */
    async warmCacheForIdentity(identityId: string): Promise<number> {
        const tokens = await this.findActiveByIdentityId(identityId);

        await Promise.all(tokens.map((token) => _cacheToken(token)));

        return tokens.length;
    },
};
