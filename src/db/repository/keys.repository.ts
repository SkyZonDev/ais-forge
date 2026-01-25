import {
    and,
    asc,
    count,
    desc,
    eq,
    gt,
    isNull,
    lt,
    SQL,
    sql,
} from 'drizzle-orm';
import type { PaginationDirection } from '../../types/pagination';
import { db } from '../../utils/db';
import type { signingAlgorithm } from '../schema';
import * as schema from '../schema';
import {
    _buildPaginatedResult,
    buildCursorCondition,
    type Cursor,
    decodeCursor,
    type PaginatedResult,
} from './utils';

// ============================================================================
// TYPES
// ============================================================================

/** Supported signing algorithms derived from schema enum */
type SigningAlgorithm = (typeof signingAlgorithm)[number];

/** Input data for creating a new signing key */
interface CreateSigningKeyInput {
    /** Unique key identifier (e.g., "2025-01-a3f9") */
    kid: string;
    /** Signing algorithm to use */
    algorithm?: SigningAlgorithm;
    /** Private key encrypted with master key */
    privateKeyEncrypted: string;
    /** Public key in PEM format for JWKS exposure */
    publicKey: string;
    /** Key expiration timestamp */
    expiresAt: Date;
}

/** Options for paginated key listing */
interface ListKeysOptions {
    /** Maximum number of keys to return (default: 20) */
    limit?: number;
    /** Cursor for pagination (base64url encoded) */
    cursor?: Cursor;
    /** Pagination direction (default: forward) */
    direction?: PaginationDirection;
    /** Filter by active status only */
    activeOnly?: boolean;
    /** Include total count in response (expensive on large tables) */
    includeTotalCount?: boolean;
}

/** Inferred signing key type from schema */
type SigningKey = typeof schema.signingKeys.$inferSelect;

/** Partial update input for signing keys */
type UpdateSigningKeyInput = Partial<
    Pick<SigningKey, 'isActive' | 'rotatedAt' | 'expiresAt'>
>;

// ============================================================================
// REPOSITORY
// ============================================================================

export const keysRepository = {
    // ========================================================================
    // CREATE OPERATIONS
    // ========================================================================

    /**
     * Creates a new signing key in the database.
     *
     * The key is created as active by default. The private key should be
     * encrypted with the master key before being passed to this function.
     *
     * @param input - The signing key data to insert
     * @returns The newly created signing key record
     * @throws DatabaseError if insertion fails (e.g., duplicate kid)
     *
     * @example
     * ```typescript
     * const key = await keysRepository.create({
     *   kid: '2025-01-a3f9',
     *   algorithm: 'ES256',
     *   privateKeyEncrypted: encryptedPrivateKey,
     *   publicKey: pemPublicKey,
     *   expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days
     * });
     * ```
     */
    async create(input: CreateSigningKeyInput): Promise<SigningKey | null> {
        const [key] = await db
            .insert(schema.signingKeys)
            .values({
                kid: input.kid,
                algorithm: input.algorithm ?? 'ES256',
                privateKeyEncrypted: input.privateKeyEncrypted,
                publicKey: input.publicKey,
                expiresAt: input.expiresAt,
            })
            .returning();

        return key ?? null;
    },

    // ========================================================================
    // READ OPERATIONS
    // ========================================================================

    /**
     * Retrieves a signing key by its UUID.
     *
     * @param id - The UUID of the signing key
     * @returns The signing key if found, null otherwise
     *
     * @example
     * ```typescript
     * const key = await keysRepository.findById('550e8400-e29b-41d4-a716-446655440000');
     * if (key) {
     *   console.log(`Found key: ${key.kid}`);
     * }
     * ```
     */
    async findById(id: string): Promise<SigningKey | null> {
        const [key] = await db
            .select()
            .from(schema.signingKeys)
            .where(eq(schema.signingKeys.id, id))
            .limit(1);

        return key ?? null;
    },

    /**
     * Retrieves a signing key by its Key ID (kid).
     *
     * This is the primary lookup method during JWT validation, as the kid
     * is embedded in the JWT header to identify which key was used for signing.
     *
     * @param kid - The unique key identifier (e.g., "2025-01-a3f9")
     * @returns The signing key if found, null otherwise
     *
     * @example
     * ```typescript
     * // During JWT validation
     * const kid = extractKidFromJwtHeader(token);
     * const key = await keysRepository.findByKid(kid);
     * if (!key) {
     *   throw new InvalidTokenError('Unknown signing key');
     * }
     * ```
     */
    async findByKid(kid: string): Promise<SigningKey | null> {
        const [key] = await db
            .select()
            .from(schema.signingKeys)
            .where(eq(schema.signingKeys.kid, kid))
            .limit(1);

        return key ?? null;
    },

    /**
     * Retrieves the current active signing key for token generation.
     *
     * Returns the most recently created active key that hasn't been rotated.
     * This should be used when signing new tokens.
     *
     * @returns The current active signing key, or null if none available
     * @throws NoActiveKeyError should be handled by caller if null
     *
     * @example
     * ```typescript
     * const activeKey = await keysRepository.findCurrentActive();
     * if (!activeKey) {
     *   throw new NoActiveKeyError('No active signing key available');
     * }
     * const token = signJwt(payload, activeKey.privateKeyEncrypted, activeKey.kid);
     * ```
     */
    async findCurrentActive(): Promise<SigningKey | null> {
        const [key] = await db
            .select()
            .from(schema.signingKeys)
            .where(
                and(
                    eq(schema.signingKeys.isActive, true),
                    isNull(schema.signingKeys.rotatedAt)
                )
            )
            .orderBy(desc(schema.signingKeys.createdAt))
            .limit(1);

        return key ?? null;
    },

    /**
     * Retrieves the current active signing key for a specific algorithm.
     *
     * Useful for systems supporting multiple algorithms simultaneously
     * (e.g., during post-quantum transition where both classic and PQC
     * algorithms need to be available).
     *
     * @param algorithm - The signing algorithm to filter by
     * @returns The active signing key for the algorithm, or null if none available
     *
     * @example
     * ```typescript
     * // Get active ML-DSA-65 key for post-quantum signing
     * const pqKey = await keysRepository.findCurrentActiveByAlgorithm('ML-DSA-65');
     * if (!pqKey) {
     *   // Fallback to classic algorithm or generate new PQ key
     *   const classicKey = await keysRepository.findCurrentActive();
     * }
     * ```
     */
    async findCurrentActiveByAlgorithm(
        algorithm: SigningAlgorithm
    ): Promise<SigningKey | null> {
        const [key] = await db
            .select()
            .from(schema.signingKeys)
            .where(
                and(
                    eq(schema.signingKeys.isActive, true),
                    eq(schema.signingKeys.algorithm, algorithm),
                    isNull(schema.signingKeys.rotatedAt)
                )
            )
            .orderBy(desc(schema.signingKeys.createdAt))
            .limit(1);

        return key ?? null;
    },

    /**
     * Lists all signing keys with cursor-based pagination.
     *
     * Supports filtering by active status and bidirectional navigation.
     * Uses composite cursor (createdAt + id) for stable pagination during key rotation.
     *
     * @param options - Pagination and filtering options
     * @returns Paginated result with keys and navigation metadata
     *
     * @example
     * ```typescript
     * // First page (newest first)
     * const page1 = await keysRepository.findAll({
     *   limit: 10,
     *   activeOnly: true,
     *   includeTotalCount: true,
     * });
     *
     * // Next page (older keys)
     * if (page1.pagination.hasNextPage) {
     *   const page2 = await keysRepository.findAll({
     *     limit: 10,
     *     cursor: page1.pagination.endCursor!,
     *     direction: 'forward',
     *     activeOnly: true,
     *   });
     * }
     *
     * // Previous page (newer keys)
     * if (page2.pagination.hasPreviousPage) {
     *   const backToPage1 = await keysRepository.findAll({
     *     limit: 10,
     *     cursor: page2.pagination.startCursor!,
     *     direction: 'backward',
     *     activeOnly: true,
     *   });
     * }
     * ```
     */
    async findAll(
        options: ListKeysOptions = {}
    ): Promise<PaginatedResult<SigningKey>> {
        const {
            limit = 20,
            cursor,
            direction = 'forward',
            activeOnly = false,
            includeTotalCount = false,
        } = options;

        // Build where conditions
        const conditions: SQL[] = [];

        if (activeOnly) {
            conditions.push(eq(schema.signingKeys.isActive, true));
        }

        // Cursor-based pagination using composite cursor
        if (cursor) {
            const decodedCursor = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(
                    schema.signingKeys,
                    decodedCursor,
                    direction
                )
            );
        }

        // Execute query with limit + 1 to detect if more records exist
        const keys = await db
            .select()
            .from(schema.signingKeys)
            .where(conditions.length > 0 ? and(...conditions) : undefined)
            .orderBy(
                // Always order DESC (newest first), reverse results for backward
                desc(schema.signingKeys.createdAt),
                desc(schema.signingKeys.id)
            )
            .limit(limit + 1);

        // Determine if more records exist
        const hasMore = keys.length > limit;
        const results = hasMore ? keys.slice(0, limit) : keys;

        // Reverse results for backward pagination to maintain consistent order
        if (direction === 'backward') {
            results.reverse();
        }

        // Optional total count (can be expensive on large tables)
        let totalCount: number | undefined;
        if (includeTotalCount) {
            const countResult = await db
                .select({ total: count() })
                .from(schema.signingKeys)
                .where(
                    activeOnly
                        ? eq(schema.signingKeys.isActive, true)
                        : undefined
                );

            totalCount = countResult[0]?.total ?? 0;
        }

        return _buildPaginatedResult(results, {
            cursor,
            direction,
            hasMore,
            totalCount,
        });
    },

    /**
     * Retrieves all active public keys for JWKS endpoint exposure.
     *
     * Returns only the public key data needed for JWKS (kid, algorithm, publicKey).
     * Includes both current and recently rotated keys to allow token validation
     * during key rotation grace periods.
     *
     * @returns Array of public key data for JWKS
     *
     * @example
     * ```typescript
     * // GET /.well-known/jwks.json
     * const publicKeys = await keysRepository.findPublicKeysForJwks();
     * const jwks = {
     *   keys: publicKeys.map(k => convertToJwk(k.publicKey, k.kid, k.algorithm)),
     * };
     * ```
     */
    async findPublicKeysForJwks(): Promise<
        Pick<SigningKey, 'kid' | 'algorithm' | 'publicKey'>[]
    > {
        return db
            .select({
                kid: schema.signingKeys.kid,
                algorithm: schema.signingKeys.algorithm,
                publicKey: schema.signingKeys.publicKey,
            })
            .from(schema.signingKeys)
            .where(eq(schema.signingKeys.isActive, true))
            .orderBy(desc(schema.signingKeys.createdAt));
    },

    /**
     * Counts signing keys matching the specified criteria.
     *
     * @param activeOnly - If true, count only active keys
     * @returns The count of matching keys
     *
     * @example
     * ```typescript
     * const activeCount = await keysRepository.count(true);
     * if (activeCount === 0) {
     *   await alertOps('No active signing keys!');
     * }
     * ```
     */
    async count(activeOnly = false): Promise<number> {
        const result = await db
            .select({ total: count() })
            .from(schema.signingKeys)
            .where(
                activeOnly ? eq(schema.signingKeys.isActive, true) : undefined
            );

        return result[0]?.total ?? 0;
    },

    // ========================================================================
    // UPDATE OPERATIONS
    // ========================================================================

    /**
     * Updates a signing key by its UUID.
     *
     * Only allows updating specific fields (isActive, rotatedAt, expiresAt).
     * Cryptographic material (keys, algorithm) cannot be modified.
     *
     * @param id - The UUID of the signing key to update
     * @param input - The fields to update
     * @returns The updated signing key, or null if not found
     *
     * @example
     * ```typescript
     * const updated = await keysRepository.update(keyId, {
     *   isActive: false,
     *   rotatedAt: new Date(),
     * });
     * ```
     */
    async update(
        id: string,
        input: UpdateSigningKeyInput
    ): Promise<SigningKey | null> {
        const [key] = await db
            .update(schema.signingKeys)
            .set(input)
            .where(eq(schema.signingKeys.id, id))
            .returning();

        return key ?? null;
    },

    /**
     * Rotates a signing key, marking it as no longer primary.
     *
     * Sets the rotatedAt timestamp to now. The key remains active for
     * validation but won't be used for signing new tokens.
     *
     * @param id - The UUID of the signing key to rotate
     * @returns The rotated signing key, or null if not found
     *
     * @example
     * ```typescript
     * // During key rotation ceremony
     * const newKey = await keysRepository.create({ ... });
     * const oldKey = await keysRepository.rotate(currentKeyId);
     * await auditLog('key_rotated', { oldKid: oldKey.kid, newKid: newKey.kid });
     * ```
     */
    async rotate(id: string): Promise<SigningKey | null> {
        const [key] = await db
            .update(schema.signingKeys)
            .set({ rotatedAt: new Date() })
            .where(
                and(
                    eq(schema.signingKeys.id, id),
                    isNull(schema.signingKeys.rotatedAt)
                )
            )
            .returning();

        return key ?? null;
    },

    /**
     * Deactivates a signing key, preventing its use for both signing and validation.
     *
     * This is a security operation used when a key is compromised or
     * needs immediate revocation. Tokens signed with this key will fail validation.
     *
     * @param id - The UUID of the signing key to deactivate
     * @returns The deactivated signing key, or null if not found
     *
     * @example
     * ```typescript
     * // Emergency key revocation
     * const compromisedKey = await keysRepository.deactivate(keyId);
     * await auditLog('key_deactivated', {
     *   kid: compromisedKey.kid,
     *   reason: 'potential_compromise',
     *   severity: 'critical',
     * });
     * ```
     */
    async deactivate(id: string): Promise<SigningKey | null> {
        const [key] = await db
            .update(schema.signingKeys)
            .set({
                isActive: false,
                rotatedAt: sql`COALESCE(${schema.signingKeys.rotatedAt}, NOW())`,
            })
            .where(eq(schema.signingKeys.id, id))
            .returning();

        return key ?? null;
    },

    // ========================================================================
    // DELETE OPERATIONS
    // ========================================================================

    /**
     * Permanently deletes a signing key by its UUID.
     *
     * ⚠️ WARNING: This is a destructive operation. Tokens signed with this
     * key will no longer be validatable. Use deactivate() for graceful removal.
     *
     * @param id - The UUID of the signing key to delete
     * @returns True if the key was deleted, false if not found
     *
     * @example
     * ```typescript
     * // Only for cleanup of long-expired keys
     * const deleted = await keysRepository.deleteById(expiredKeyId);
     * if (deleted) {
     *   await auditLog('key_deleted', { id: expiredKeyId });
     * }
     * ```
     */
    async deleteById(id: string): Promise<boolean> {
        const result = await db
            .delete(schema.signingKeys)
            .where(eq(schema.signingKeys.id, id))
            .returning({ id: schema.signingKeys.id });

        return result.length > 0;
    },

    /**
     * Purges all expired and inactive signing keys from the database.
     *
     * This cleanup operation removes keys that are both expired AND inactive.
     * Keys that are expired but still active are preserved for audit purposes.
     * Should be run periodically via scheduled job.
     *
     * @returns The number of keys deleted
     *
     * @example
     * ```typescript
     * // Scheduled cleanup job (e.g., daily at 3 AM)
     * const purgedCount = await keysRepository.purgeExpired();
     * console.log(`Purged ${purgedCount} expired signing keys`);
     * ```
     */
    async purgeExpired(): Promise<number> {
        const result = await db
            .delete(schema.signingKeys)
            .where(
                and(
                    lt(schema.signingKeys.expiresAt, new Date()),
                    eq(schema.signingKeys.isActive, false)
                )
            )
            .returning({ id: schema.signingKeys.id });

        return result.length;
    },

    // ========================================================================
    // UTILITY OPERATIONS
    // ========================================================================

    /**
     * Checks if a key identifier (kid) already exists in the database.
     *
     * Use this before generating a new key to ensure uniqueness.
     *
     * @param kid - The key identifier to check
     * @returns True if the kid exists, false otherwise
     *
     * @example
     * ```typescript
     * let kid = generateKid();
     * while (await keysRepository.existsByKid(kid)) {
     *   kid = generateKid(); // Regenerate if collision
     * }
     * ```
     */
    async existsByKid(kid: string): Promise<boolean> {
        const [result] = await db
            .select({ exists: sql<boolean>`1` })
            .from(schema.signingKeys)
            .where(eq(schema.signingKeys.kid, kid))
            .limit(1);

        return result !== undefined;
    },

    /**
     * Retrieves keys that are approaching expiration.
     *
     * Used for proactive key rotation alerts. Returns active keys
     * that will expire within the specified threshold.
     *
     * @param thresholdDays - Number of days before expiration to alert (default: 30)
     * @returns Array of keys approaching expiration
     *
     * @example
     * ```typescript
     * // Daily check for keys needing rotation
     * const expiringKeys = await keysRepository.findExpiringSoon(14);
     * for (const key of expiringKeys) {
     *   await alertOps(`Key ${key.kid} expires in less than 14 days`);
     * }
     * ```
     */
    async findExpiringSoon(thresholdDays = 30): Promise<SigningKey[]> {
        const thresholdDate = new Date();
        thresholdDate.setDate(thresholdDate.getDate() + thresholdDays);

        return db
            .select()
            .from(schema.signingKeys)
            .where(
                and(
                    eq(schema.signingKeys.isActive, true),
                    lt(schema.signingKeys.expiresAt, thresholdDate),
                    gt(schema.signingKeys.expiresAt, new Date())
                )
            )
            .orderBy(asc(schema.signingKeys.expiresAt));
    },
};
