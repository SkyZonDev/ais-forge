import type { JWK } from 'jose';
import { auditRepository } from '../../db/repository/audit.repository';
import { keysRepository } from '../../db/repository/keys.repository';
import { ApiError } from '../../utils/api/api-error';
import {
    createJWKS,
    createJWT,
    decryptPrivateKey,
    encryptPrivateKey,
    generateKeyPair,
    type SigningAlgorithm,
} from '../../utils/crypto';

// ============================================================================
// TYPES
// ============================================================================

/** Options for generating a new signing key */
interface GenerateKeyOptions {
    /** Signing algorithm (default: ES256) */
    algorithm?: SigningAlgorithm;
    /** Custom key identifier (auto-generated if not provided) */
    kid?: string;
    /** Key validity duration in days (default: 90) */
    validityDays?: number;
}

/** Options for key rotation */
interface RotateKeyOptions {
    /** Algorithm for the new key (default: same as current) */
    algorithm?: SigningAlgorithm;
    /** Validity duration for the new key in days (default: 90) */
    validityDays?: number;
    /** Reason for rotation (for audit log) */
    reason?: string;
}

/** Options for creating a signed JWT */
interface CreateTokenOptions {
    /** Token expiration duration (e.g., '15m', '1h', '7d') */
    expiresIn?: string;
    /** Token issuer */
    issuer?: string;
    /** Token audience */
    audience?: string;
    /**
     * Specific algorithm to use for signing.
     * If specified, will use an active key with this algorithm.
     * If not specified, uses the most recent active key (any algorithm).
     */
    algorithm?: SigningAlgorithm;
    /**
     * Auto-generate a key if no active key exists for the requested algorithm.
     * Only applies when `algorithm` is specified. Default: false
     */
    autoGenerateKey?: boolean;
}

/** JWT payload structure */
interface TokenPayload {
    /** Subject (typically user/identity ID) */
    sub: string;
    /** Scope */
    scope: string;
    /** Session id */
    sid?: string;
    /** Name */
    name?: string;
    /** AMR */
    amr?: string[];
    /** Email */
    email?: string;
    /** Additional claims */
    [key: string]: unknown;
}

/** JWKS response structure */
interface JWKSResponse {
    keys: JWK[];
}

/** Key health status */
interface KeyHealthStatus {
    /** Whether the system has an active signing key */
    hasActiveKey: boolean;
    /** Current active key identifier */
    activeKid: string | null;
    /** Number of active keys (including rotated but still valid) */
    activeKeysCount: number;
    /** Keys expiring within threshold */
    expiringKeys: Array<{
        kid: string;
        expiresAt: Date;
        daysUntilExpiration: number;
    }>;
    /** Whether rotation is recommended */
    rotationRecommended: boolean;
}

// ============================================================================
// KEY GENERATION
// ============================================================================

/**
 * Generates a new signing key and stores it in the database.
 *
 * Creates a cryptographic key pair, encrypts the private key with the
 * master key, and stores it securely. The new key becomes immediately
 * available for signing operations.
 *
 * @param options - Key generation options
 * @returns The created signing key metadata (without decrypted private key)
 * @throws ApiError with code 'KEY_GENERATION_FAILED' if key generation fails
 * @throws ApiError with code 'MASTER_KEY_NOT_CONFIGURED' if master key is missing
 *
 * @example
 * ```typescript
 * // Generate a new ES256 key valid for 90 days
 * const key = await generateSigningKey();
 *
 * // Generate a post-quantum key with custom validity
 * const pqKey = await generateSigningKey({
 *   algorithm: 'ML-DSA-65',
 *   validityDays: 180,
 * });
 * ```
 */
export async function generateSigningKey(options: GenerateKeyOptions = {}) {
    const { algorithm = 'ES256', kid, validityDays = 90 } = options;

    // Verify master key is configured
    const masterKey = process.env.MASTER_ENCRYPTION_KEY;
    if (!masterKey) {
        throw new ApiError(
            'Master encryption key not configured',
            500,
            'MASTER_KEY_NOT_CONFIGURED'
        );
    }

    const masterKeyBuffer = Buffer.from(masterKey, 'base64');

    // Generate key pair
    const keyPair = await generateKeyPair(algorithm, kid);

    // Encrypt private key for storage
    const encryptedKeyPair = await encryptPrivateKey(
        keyPair.privateKey,
        masterKeyBuffer
    );

    // Calculate expiration date
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + validityDays);

    // Store in database
    const signingKey = await keysRepository.create({
        kid: keyPair.kid,
        algorithm: keyPair.algorithm,
        privateKeyEncrypted: encryptedKeyPair,
        publicKey: keyPair.publicKey,
        expiresAt,
    });

    if (!signingKey) {
        throw new ApiError(
            'Failed to store signing key',
            500,
            'KEY_GENERATION_FAILED'
        );
    }

    // Audit log
    await auditRepository.create({
        eventType: 'security.key.generated',
        eventCategory: 'security',
        severity: 'info',
        success: true,
        metadata: {
            kid: signingKey.kid,
            algorithm: signingKey.algorithm,
            expiresAt: signingKey.expiresAt.toISOString(),
        },
    });

    return {
        id: signingKey.id,
        kid: signingKey.kid,
        algorithm: signingKey.algorithm,
        publicKey: signingKey.publicKey,
        isActive: signingKey.isActive,
        createdAt: signingKey.createdAt,
        expiresAt: signingKey.expiresAt,
    };
}

// ============================================================================
// KEY ROTATION
// ============================================================================

/**
 * Rotates the current active signing key.
 *
 * Creates a new signing key and marks the current active key as rotated.
 * The old key remains active for token validation during the grace period,
 * but new tokens will be signed with the new key.
 *
 * @param options - Rotation options
 * @returns Object containing the new key and the rotated old key
 * @throws ApiError with code 'NO_ACTIVE_KEY' if no active key exists to rotate
 * @throws ApiError with code 'ROTATION_FAILED' if rotation fails
 *
 * @example
 * ```typescript
 * // Rotate with same algorithm
 * const { newKey, oldKey } = await rotateSigningKey({
 *   reason: 'scheduled_rotation',
 * });
 *
 * // Rotate to a post-quantum algorithm
 * const { newKey } = await rotateSigningKey({
 *   algorithm: 'ML-DSA-65',
 *   reason: 'algorithm_upgrade',
 * });
 * ```
 */
export async function rotateSigningKey(options: RotateKeyOptions = {}) {
    const {
        algorithm,
        validityDays = 90,
        reason = 'manual_rotation',
    } = options;

    // Get current active key
    const currentKey = await keysRepository.findCurrentActive();
    if (!currentKey) {
        throw new ApiError(
            'No active signing key to rotate',
            400,
            'NO_ACTIVE_KEY'
        );
    }

    // Generate new key (use same algorithm if not specified)
    const newKey = await generateSigningKey({
        algorithm: algorithm ?? currentKey.algorithm,
        validityDays,
    });

    // Mark old key as rotated
    const rotatedKey = await keysRepository.rotate(currentKey.id);
    if (!rotatedKey) {
        throw new ApiError('Failed to rotate old key', 500, 'ROTATION_FAILED');
    }

    // Audit log
    await auditRepository.create({
        eventType: 'security.key.rotated',
        eventCategory: 'security',
        severity: 'info',
        success: true,
        metadata: {
            oldKid: rotatedKey.kid,
            newKid: newKey.kid,
            reason,
            oldAlgorithm: rotatedKey.algorithm,
            newAlgorithm: newKey.algorithm,
        },
    });

    return {
        newKey,
        oldKey: {
            id: rotatedKey.id,
            kid: rotatedKey.kid,
            algorithm: rotatedKey.algorithm,
            rotatedAt: rotatedKey.rotatedAt,
        },
    };
}

// ============================================================================
// KEY DEACTIVATION
// ============================================================================

/**
 * Deactivates a signing key, preventing its use for signing and validation.
 *
 * This is a security operation for compromised or deprecated keys.
 * All tokens signed with this key will fail validation after deactivation.
 *
 * @param keyId - The UUID of the key to deactivate
 * @param reason - Reason for deactivation (for audit log)
 * @returns The deactivated key metadata
 * @throws ApiError with code 'KEY_NOT_FOUND' if key doesn't exist
 *
 * @example
 * ```typescript
 * // Emergency deactivation of compromised key
 * const deactivated = await deactivateSigningKey(keyId, 'potential_compromise');
 * ```
 */
export async function deactivateSigningKey(keyId: string, reason: string) {
    const key = await keysRepository.deactivate(keyId);

    if (!key) {
        throw new ApiError('Signing key not found', 404, 'KEY_NOT_FOUND');
    }

    // Audit log with critical severity for security event
    await auditRepository.create({
        eventType: 'security.key.deactivated',
        eventCategory: 'security',
        severity: 'critical',
        success: true,
        metadata: {
            kid: key.kid,
            reason,
            algorithm: key.algorithm,
        },
    });

    return {
        id: key.id,
        kid: key.kid,
        algorithm: key.algorithm,
        deactivatedAt: key.rotatedAt,
    };
}

// ============================================================================
// JWKS ENDPOINT
// ============================================================================

/**
 * Builds the JWKS response for the /.well-known/jwks.json endpoint.
 *
 * Returns all active public keys in JWK format, allowing clients to
 * validate tokens signed by any active key (including recently rotated ones).
 *
 * @returns JWKS object containing all active public keys
 *
 * @example
 * ```typescript
 * // In your route handler
 * app.get('/.well-known/jwks.json', async (req, res) => {
 *   const jwks = await getJWKS();
 *   res.json(jwks);
 * });
 * ```
 */
export async function getJWKS(): Promise<JWKSResponse> {
    const publicKeys = await keysRepository.findPublicKeysForJwks();

    if (publicKeys.length === 0) {
        // Return empty JWKS rather than error (valid state during initial setup)
        return { keys: [] };
    }

    const jwks = await createJWKS(
        publicKeys.map((key) => ({
            publicKey: key.publicKey,
            algorithm: key.algorithm as SigningAlgorithm,
            kid: key.kid,
        }))
    );

    return jwks;
}

// ============================================================================
// TOKEN OPERATIONS
// ============================================================================

/**
 * Creates a signed JWT using an active signing key.
 *
 * By default, uses the most recent active key (any algorithm). When an
 * algorithm is specified, it will use an active key with that algorithm,
 * optionally auto-generating one if none exists.
 *
 * @param payload - The token payload containing claims
 * @param options - Token options (expiration, issuer, audience, algorithm)
 * @returns Signed JWT string
 * @throws ApiError with code 'NO_ACTIVE_KEY' if no suitable signing key exists
 * @throws ApiError with code 'TOKEN_SIGNING_FAILED' if signing fails
 *
 * @example
 * ```typescript
 * // Create an access token with default (most recent) key
 * const accessToken = await signToken(
 *   { sub: userId, scope: 'read write', role: 'admin' },
 *   { expiresIn: '15m', issuer: 'auth.example.com' }
 * );
 *
 * // Create a token with a specific algorithm (post-quantum)
 * const pqToken = await signToken(
 *   { sub: userId, type: 'sensitive' },
 *   { expiresIn: '5m', algorithm: 'ML-DSA-65' }
 * );
 *
 * // Auto-generate key if needed for the algorithm
 * const token = await signToken(
 *   { sub: userId },
 *   { algorithm: 'ML-DSA-87', autoGenerateKey: true }
 * );
 * ```
 */
export async function signToken(
    payload: TokenPayload,
    options: CreateTokenOptions = {}
): Promise<string> {
    const {
        expiresIn,
        issuer,
        audience,
        algorithm,
        autoGenerateKey = false,
    } = options;

    // Get appropriate signing key based on algorithm preference
    let activeKey = algorithm
        ? await keysRepository.findCurrentActiveByAlgorithm(algorithm)
        : await keysRepository.findCurrentActive();

    // Handle missing key for specific algorithm
    if (!activeKey && algorithm) {
        if (autoGenerateKey) {
            // Auto-generate a key for this algorithm
            const newKey = await generateSigningKey({ algorithm });
            activeKey = await keysRepository.findById(newKey.id);
        } else {
            throw new ApiError(
                `No active signing key for algorithm ${algorithm}. ` +
                    'Generate one first or use autoGenerateKey option.',
                400,
                'NO_KEY_FOR_ALGORITHM'
            );
        }
    }

    if (!activeKey) {
        throw new ApiError(
            'No active signing key available',
            500,
            'NO_ACTIVE_KEY'
        );
    }

    // Decrypt private key
    const masterKey = process.env.MASTER_ENCRYPTION_KEY;
    if (!masterKey) {
        throw new ApiError(
            'Master encryption key not configured',
            500,
            'MASTER_KEY_NOT_CONFIGURED'
        );
    }

    const masterKeyBuffer = Buffer.from(masterKey, 'base64');

    const privateKey = await decryptPrivateKey(
        activeKey.privateKeyEncrypted,
        masterKeyBuffer
    );

    // Build full payload with standard claims
    const fullPayload: Record<string, unknown> = {
        ...payload,
        ...(issuer && { iss: issuer }),
        ...(audience && { aud: audience }),
    };

    // Sign and return JWT
    return await createJWT(
        fullPayload,
        privateKey,
        activeKey.algorithm as SigningAlgorithm,
        activeKey.kid,
        expiresIn
    );
}

/**
 * Retrieves the signing key for a given key identifier (kid).
 *
 * Used during token validation to get the public key for signature verification.
 * Only returns active keys to prevent validation with deactivated keys.
 *
 * @param kid - The key identifier from the JWT header
 * @returns The signing key metadata with public key
 * @throws ApiError with code 'KEY_NOT_FOUND' if key doesn't exist
 * @throws ApiError with code 'KEY_INACTIVE' if key has been deactivated
 *
 * @example
 * ```typescript
 * // During token validation
 * const { kid } = decodeJwtHeader(token);
 * const key = await getSigningKeyByKid(kid);
 * const isValid = await verifySignature(token, key.publicKey, key.algorithm);
 * ```
 */
export async function getSigningKeyByKid(kid: string) {
    const key = await keysRepository.findByKid(kid);

    if (!key) {
        throw new ApiError('Signing key not found', 404, 'KEY_NOT_FOUND');
    }

    if (!key.isActive) {
        throw new ApiError(
            'Signing key has been deactivated',
            401,
            'KEY_INACTIVE'
        );
    }

    return {
        id: key.id,
        kid: key.kid,
        algorithm: key.algorithm,
        publicKey: key.publicKey,
        isActive: key.isActive,
    };
}

// ============================================================================
// KEY HEALTH & MONITORING
// ============================================================================

/**
 * Gets the health status of the signing key system.
 *
 * Provides an overview of the key infrastructure including active keys,
 * expiring keys, and rotation recommendations. Use this for monitoring
 * dashboards and health checks.
 *
 * @param expirationThresholdDays - Days before expiration to flag keys (default: 30)
 * @returns Key health status object
 *
 * @example
 * ```typescript
 * // Health check endpoint
 * app.get('/health/keys', async (req, res) => {
 *   const status = await getKeyHealthStatus();
 *
 *   if (!status.hasActiveKey) {
 *     return res.status(503).json({ status: 'unhealthy', ...status });
 *   }
 *
 *   if (status.rotationRecommended) {
 *     return res.status(200).json({ status: 'warning', ...status });
 *   }
 *
 *   res.json({ status: 'healthy', ...status });
 * });
 * ```
 */
export async function getKeyHealthStatus(
    expirationThresholdDays = 30
): Promise<KeyHealthStatus> {
    const [activeKey, activeKeysCount, expiringKeys] = await Promise.all([
        keysRepository.findCurrentActive(),
        keysRepository.count(true),
        keysRepository.findExpiringSoon(expirationThresholdDays),
    ]);

    const now = new Date();
    const expiringKeysFormatted = expiringKeys.map((key) => ({
        kid: key.kid,
        expiresAt: key.expiresAt,
        daysUntilExpiration: Math.ceil(
            (key.expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
        ),
    }));

    // Rotation is recommended if:
    // 1. Current active key is expiring soon
    // 2. There are fewer than 2 active keys
    // 3. Any key is expiring within 14 days
    const rotationRecommended =
        !activeKey ||
        activeKeysCount < 2 ||
        expiringKeysFormatted.some((k) => k.daysUntilExpiration <= 14);

    return {
        hasActiveKey: !!activeKey,
        activeKid: activeKey?.kid ?? null,
        activeKeysCount,
        expiringKeys: expiringKeysFormatted,
        rotationRecommended,
    };
}

/**
 * Checks for expiring keys and returns alerts.
 *
 * Use this in scheduled jobs to proactively notify about keys needing rotation.
 *
 * @param thresholdDays - Days before expiration to alert (default: 14)
 * @returns Array of alert messages for expiring keys
 *
 * @example
 * ```typescript
 * // Daily scheduled job
 * const alerts = await checkExpiringKeys(14);
 * for (const alert of alerts) {
 *   await sendOpsAlert(alert);
 * }
 * ```
 */
export async function checkExpiringKeys(thresholdDays = 14): Promise<string[]> {
    const expiringKeys = await keysRepository.findExpiringSoon(thresholdDays);
    const now = new Date();

    return expiringKeys.map((key) => {
        const daysLeft = Math.ceil(
            (key.expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
        );
        return `Signing key ${key.kid} (${key.algorithm}) expires in ${daysLeft} days`;
    });
}

// ============================================================================
// MAINTENANCE OPERATIONS
// ============================================================================

/**
 * Purges expired and inactive signing keys from the database.
 *
 * Removes keys that are both expired AND inactive. This is a cleanup
 * operation that should be run periodically to maintain database hygiene.
 *
 * @returns Number of keys purged
 *
 * @example
 * ```typescript
 * // Scheduled cleanup job (e.g., daily at 3 AM)
 * const purgedCount = await purgeExpiredKeys();
 * console.log(`Purged ${purgedCount} expired signing keys`);
 * ```
 */
export async function purgeExpiredKeys(): Promise<number> {
    const purgedCount = await keysRepository.purgeExpired();

    if (purgedCount > 0) {
        await auditRepository.create({
            eventType: 'security.key.purged',
            eventCategory: 'security',
            severity: 'info',
            success: true,
            metadata: {
                purgedCount,
            },
        });
    }

    return purgedCount;
}

/**
 * Initializes the signing key system if no keys exist.
 *
 * Creates an initial signing key if the system has no active keys.
 * Useful for first-time setup or disaster recovery.
 *
 * @param algorithm - Algorithm for the initial key (default: ES256)
 * @returns The initial key if created, null if keys already exist
 *
 * @example
 * ```typescript
 * // Application startup
 * const initialKey = await initializeSigningKeys('ML-DSA-65');
 * if (initialKey) {
 *   console.log(`Created initial signing key: ${initialKey.kid}`);
 * }
 * ```
 */
export async function initializeSigningKeys(
    algorithm: SigningAlgorithm = 'ES256'
) {
    const existingCount = await keysRepository.count(true);

    if (existingCount > 0) {
        return null;
    }

    const key = await generateSigningKey({ algorithm });

    await auditRepository.create({
        eventType: 'security.key.initialized',
        eventCategory: 'security',
        severity: 'warning',
        success: true,
        metadata: {
            kid: key.kid,
            algorithm: key.algorithm,
            reason: 'no_existing_keys',
        },
    });

    return key;
}
