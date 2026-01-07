import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
    slh_dsa_sha2_192f,
    slh_dsa_shake_192f,
} from '@noble/post-quantum/slh-dsa.js';
import { hash, verify } from '@node-rs/argon2';
import * as jose from 'jose';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

/**
 * Supported digital signature algorithms.
 *
 * Classic algorithms (recommended until 2030-2035):
 * - EdDSA: Ed25519 curve, fast and modern
 * - ES256/ES384: ECDSA with NIST curves P-256/P-384
 * - RS256: RSA 2048-bit, legacy compatibility only
 *
 * Post-quantum algorithms (NIST FIPS 204/205, recommended for 2025+):
 * - ML-DSA-44/65/87: Lattice-based (Dilithium), fast verification
 * - SLH-DSA-SHA2-192f: Hash-based (SPHINCS+), conservative choice
 *
 * @see https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf
 */
export type SigningAlgorithm =
    | 'EdDSA'
    | 'ES256'
    | 'ES384'
    | 'RS256'
    | 'ML-DSA-44'
    | 'ML-DSA-65'
    | 'ML-DSA-87'
    | 'SLH-DSA-SHA2-192f';

/** Classic algorithms supported by jose library */
type ClassicAlgorithm = 'EdDSA' | 'ES256' | 'ES384' | 'RS256';

/** Post-quantum lattice-based algorithms (FIPS 204) */
type MLDSAAlgorithm = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

/** Post-quantum hash-based algorithms (FIPS 205) */
type SLHDSAAlgorithm = 'SLH-DSA-SHA2-192f';

/**
 * Cryptographic key pair with metadata.
 * Used for both classic (PEM) and post-quantum (base64) keys.
 */
export interface KeyPair {
    /** Public key in PEM (classic) or base64 (post-quantum) format */
    publicKey: string;
    /** Private key in PEM (classic) or base64 (post-quantum) format */
    privateKey: string;
    /** Unique key identifier for JWKS/JWT headers */
    kid: string;
    /** Algorithm used for this key pair */
    algorithm: SigningAlgorithm;
}

/**
 * Result of a signing operation.
 * For classic algorithms, signature is a JWT string.
 * For post-quantum algorithms, signature is base64-encoded raw bytes.
 */
export interface SignatureResult {
    /** Signature in base64 (post-quantum) or JWT format (classic) */
    signature: string;
    /** Algorithm used for signing */
    algorithm: SigningAlgorithm;
    /** Key identifier used for signing */
    kid: string;
}

/**
 * Key pair with encrypted private key for secure storage.
 * Private key is encrypted using AES-256-GCM with a master key.
 */
export interface EncryptedKeyPair {
    /** Public key (unencrypted, safe to expose) */
    publicKey: string;
    /** Private key encrypted with AES-256-GCM, format: iv:authTag:ciphertext */
    privateKeyEncrypted: string;
    /** Unique key identifier */
    kid: string;
    /** Algorithm for this key pair */
    algorithm: SigningAlgorithm;
}

// ============================================================================
// CONSTANTS
// ============================================================================

/** ML-DSA algorithm instances mapped by algorithm name */
const ML_DSA_INSTANCES = {
    'ML-DSA-44': ml_dsa44,
    'ML-DSA-65': ml_dsa65,
    'ML-DSA-87': ml_dsa87,
} as const;

/** SLH-DSA algorithm instances mapped by algorithm name */
const SLH_DSA_INSTANCES = {
    'SLH-DSA-SHA2-192f': slh_dsa_sha2_192f,
    'SLH-DSA-SHAKE-192f': slh_dsa_shake_192f,
} as const;

/** Duration units in seconds for JWT expiration parsing */
const DURATION_UNITS: Record<string, number> = {
    s: 1,
    m: 60,
    h: 3600,
    d: 86400,
    w: 604800,
};

// ============================================================================
// PASSWORD HASHING (Argon2id)
// ============================================================================

/**
 * Hashes a password using Argon2id algorithm.
 *
 * Uses OWASP recommended parameters for high-security applications:
 * - Memory: 64 MB (65536 KB)
 * - Time cost: 3 iterations
 * - Parallelism: 4 lanes
 *
 * @param password - Plain text password to hash
 * @returns Argon2id hash string (includes salt and parameters)
 *
 * @example
 * ```typescript
 * const hash = await hashPassword('user-password');
 * // Store hash in authMethods.credentialHash
 * ```
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */
export async function hashPassword(password: string): Promise<string> {
    return hash(password, {
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 4,
        algorithm: 2, // Argon2id
    });
}

/**
 * Verifies a password against an Argon2id hash.
 *
 * @param storedHash - Hash retrieved from database (authMethods.credentialHash)
 * @param password - Plain text password to verify
 * @returns True if password matches, false otherwise
 *
 * @example
 * ```typescript
 * const isValid = await verifyPassword(authMethod.credentialHash, inputPassword);
 * if (!isValid) throw new AuthenticationError('Invalid credentials');
 * ```
 */
export async function verifyPassword(
    storedHash: string,
    password: string
): Promise<boolean> {
    return verify(storedHash, password);
}

// ============================================================================
// KEY GENERATION
// ============================================================================

/**
 * Generates a cryptographic key pair for digital signatures.
 *
 * Supports both classic (EdDSA, ECDSA, RSA) and post-quantum (ML-DSA, SLH-DSA)
 * algorithms. Post-quantum keys are recommended for long-term security.
 *
 * @param algorithm - Signing algorithm to use
 * @param kid - Optional key identifier (auto-generated if not provided)
 * @returns Generated key pair with public/private keys and metadata
 * @throws Error if algorithm is not supported
 *
 * @example
 * ```typescript
 * // Generate a post-quantum key pair (recommended)
 * const keys = await generateKeyPair('ML-DSA-65');
 *
 * // Generate with custom kid
 * const keys = await generateKeyPair('ES256', '2025-01-prod-signing');
 * ```
 *
 * @remarks
 * - ML-DSA-65 is recommended for most use cases (NIST Category 3)
 * - ML-DSA-87 for high-security requirements (NIST Category 5)
 * - SLH-DSA is slower but ultra-conservative (hash-based)
 */
export async function generateKeyPair(
    algorithm: SigningAlgorithm,
    kid?: string
): Promise<KeyPair> {
    const keyId = kid ?? generateKid();

    switch (algorithm) {
        case 'EdDSA':
            return generateEdDSAKeyPair(keyId);

        case 'ES256':
        case 'ES384':
            return generateECDSAKeyPair(keyId, algorithm);

        case 'RS256':
            return generateRSAKeyPair(keyId);

        case 'ML-DSA-44':
        case 'ML-DSA-65':
        case 'ML-DSA-87':
            return generateMLDSAKeyPair(keyId, algorithm);

        case 'SLH-DSA-SHA2-192f':
            return generateSLHDSAKeyPair(keyId, algorithm);

        default:
            throw new Error(
                `Unsupported algorithm: ${algorithm satisfies never}`
            );
    }
}

/**
 * Generates a unique key identifier (kid) for JWKS.
 *
 * Format: YYYY-MM-XXXXXXXX (date prefix + random hex)
 * Example: 2025-01-a3f9b2c1
 *
 * @returns Unique key identifier string
 */
function generateKid(): string {
    const datePrefix = new Date().toISOString().slice(0, 7);
    const randomSuffix = randomBytes(4).toString('hex');
    return `${datePrefix}-${randomSuffix}`;
}

// ============================================================================
// CLASSIC KEY GENERATION (EdDSA, ECDSA, RSA)
// ============================================================================

/**
 * Generates an EdDSA (Ed25519) key pair.
 * Fast, modern, and widely supported. Recommended for classic signatures.
 */
async function generateEdDSAKeyPair(kid: string): Promise<KeyPair> {
    const { publicKey, privateKey } = await jose.generateKeyPair('EdDSA');

    return {
        publicKey: await jose.exportSPKI(publicKey),
        privateKey: await jose.exportPKCS8(privateKey),
        kid,
        algorithm: 'EdDSA',
    };
}

/**
 * Generates an ECDSA key pair (P-256 or P-384 curve).
 * Industry standard, good interoperability with existing systems.
 */
async function generateECDSAKeyPair(
    kid: string,
    algorithm: 'ES256' | 'ES384'
): Promise<KeyPair> {
    const { publicKey, privateKey } = await jose.generateKeyPair(algorithm);

    return {
        publicKey: await jose.exportSPKI(publicKey),
        privateKey: await jose.exportPKCS8(privateKey),
        kid,
        algorithm,
    };
}

/**
 * Generates an RSA-2048 key pair.
 * Legacy algorithm, use only for backward compatibility.
 *
 * @deprecated Prefer EdDSA or ML-DSA for new implementations
 */
async function generateRSAKeyPair(kid: string): Promise<KeyPair> {
    const { publicKey, privateKey } = await jose.generateKeyPair('RS256', {
        modulusLength: 2048,
    });

    return {
        publicKey: await jose.exportSPKI(publicKey),
        privateKey: await jose.exportPKCS8(privateKey),
        kid,
        algorithm: 'RS256',
    };
}

// ============================================================================
// POST-QUANTUM KEY GENERATION (ML-DSA, SLH-DSA)
// ============================================================================

/**
 * Generates an ML-DSA (Dilithium) key pair.
 *
 * ML-DSA is a lattice-based signature scheme from NIST FIPS 204.
 * Offers fast signing and verification with reasonable key/signature sizes.
 *
 * Security levels:
 * - ML-DSA-44: ~128-bit (Category 2), smallest keys
 * - ML-DSA-65: ~192-bit (Category 3), recommended balance
 * - ML-DSA-87: ~256-bit (Category 5), highest security
 */
function generateMLDSAKeyPair(kid: string, algorithm: MLDSAAlgorithm): KeyPair {
    const instance = ML_DSA_INSTANCES[algorithm];
    const seed = randomBytes(32);
    const keys = instance.keygen(seed);

    return {
        publicKey: Buffer.from(keys.publicKey).toString('base64'),
        privateKey: Buffer.from(keys.secretKey).toString('base64'),
        kid,
        algorithm,
    };
}

/**
 * Generates an SLH-DSA (SPHINCS+) key pair.
 *
 * SLH-DSA is a hash-based signature scheme from NIST FIPS 205.
 * Ultra-conservative choice based on well-understood hash functions.
 *
 * Trade-offs:
 * - Pros: Minimal cryptographic assumptions, small public keys
 * - Cons: Large signatures (~35KB), slow signing (~160ms)
 *
 * Variants:
 * - 'f' (fast): Faster signing, larger signatures
 * - 's' (small): Smaller signatures, slower signing
 */
function generateSLHDSAKeyPair(
    kid: string,
    algorithm: SLHDSAAlgorithm
): KeyPair {
    const instance = SLH_DSA_INSTANCES['SLH-DSA-SHA2-192f'];
    const keys = instance.keygen();

    return {
        publicKey: Buffer.from(keys.publicKey).toString('base64'),
        privateKey: Buffer.from(keys.secretKey).toString('base64'),
        kid,
        algorithm,
    };
}

// ============================================================================
// SIGNING OPERATIONS
// ============================================================================

/**
 * Signs a message using the specified algorithm and private key.
 *
 * For classic algorithms (EdDSA, ECDSA, RSA), creates a JWT with the
 * message embedded in the payload.
 *
 * For post-quantum algorithms (ML-DSA, SLH-DSA), creates a raw signature
 * in base64 format.
 *
 * @param message - Message to sign (string or Buffer)
 * @param privateKey - Private key in PEM (classic) or base64 (post-quantum)
 * @param algorithm - Signing algorithm matching the key type
 * @param kid - Key identifier for JWT header
 * @returns Signature result containing signature, algorithm, and kid
 * @throws Error if algorithm is not supported or signing fails
 *
 * @example
 * ```typescript
 * // Sign with ML-DSA
 * const result = await signMessage(
 *   JSON.stringify(payload),
 *   keyPair.privateKey,
 *   'ML-DSA-65',
 *   keyPair.kid
 * );
 * ```
 */
export async function signMessage(
    message: string | Buffer,
    privateKey: string,
    algorithm: SigningAlgorithm,
    kid: string
): Promise<SignatureResult> {
    const data = Buffer.isBuffer(message) ? message : Buffer.from(message);

    switch (algorithm) {
        case 'EdDSA':
        case 'ES256':
        case 'ES384':
        case 'RS256':
            return signWithClassic(data, privateKey, algorithm, kid);

        case 'ML-DSA-44':
        case 'ML-DSA-65':
        case 'ML-DSA-87':
            return signWithMLDSA(data, privateKey, algorithm, kid);

        case 'SLH-DSA-SHA2-192f':
            return signWithSLHDSA(data, privateKey, algorithm, kid);

        default:
            throw new Error(
                `Unsupported signing algorithm: ${algorithm satisfies never}`
            );
    }
}

/**
 * Signs data using a classic algorithm via jose library.
 * Returns a JWT with the data embedded in the payload.
 */
async function signWithClassic(
    data: Buffer,
    privateKeyPem: string,
    algorithm: ClassicAlgorithm,
    kid: string
): Promise<SignatureResult> {
    const privateKey = await jose.importPKCS8(privateKeyPem, algorithm);

    const jwt = await new jose.SignJWT({ data: data.toString('base64') })
        .setProtectedHeader({ alg: algorithm, kid })
        .setIssuedAt()
        .sign(privateKey);

    return { signature: jwt, algorithm, kid };
}

/**
 * Signs data using ML-DSA (Dilithium) algorithm.
 * Returns raw signature bytes in base64 format.
 */
function signWithMLDSA(
    data: Buffer,
    privateKeyBase64: string,
    algorithm: MLDSAAlgorithm,
    kid: string
): SignatureResult {
    const instance = ML_DSA_INSTANCES[algorithm];
    const secretKey = Buffer.from(privateKeyBase64, 'base64');
    const signature = instance.sign(data, secretKey);

    return {
        signature: Buffer.from(signature).toString('base64'),
        algorithm,
        kid,
    };
}

/**
 * Signs data using SLH-DSA (SPHINCS+) algorithm.
 * Returns raw signature bytes in base64 format.
 *
 * Note: SLH-DSA signing is slow (~160ms for SHA2-192f variant).
 */
function signWithSLHDSA(
    data: Buffer,
    privateKeyBase64: string,
    algorithm: SLHDSAAlgorithm,
    kid: string
): SignatureResult {
    const instance = SLH_DSA_INSTANCES['SLH-DSA-SHA2-192f'];
    const secretKey = Buffer.from(privateKeyBase64, 'base64');
    const signature = instance.sign(data, secretKey);

    return {
        signature: Buffer.from(signature).toString('base64'),
        algorithm,
        kid,
    };
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

/**
 * Verifies a digital signature against the original message.
 *
 * @param message - Original message that was signed
 * @param signature - Signature to verify (JWT or base64)
 * @param publicKey - Public key in PEM (classic) or base64 (post-quantum)
 * @param algorithm - Algorithm used for signing
 * @returns True if signature is valid, false otherwise
 *
 * @example
 * ```typescript
 * const isValid = await verifySignature(
 *   originalMessage,
 *   signatureResult.signature,
 *   keyPair.publicKey,
 *   'ML-DSA-65'
 * );
 * if (!isValid) throw new SignatureVerificationError();
 * ```
 *
 * @remarks
 * This function catches all errors and returns false for invalid signatures.
 * For debugging, check console output for detailed error messages.
 */
export async function verifySignature(
    message: string | Buffer,
    signature: string,
    publicKey: string,
    algorithm: SigningAlgorithm
): Promise<boolean> {
    const data = Buffer.isBuffer(message) ? message : Buffer.from(message);

    try {
        switch (algorithm) {
            case 'EdDSA':
            case 'ES256':
            case 'ES384':
            case 'RS256':
                return await verifyWithClassic(signature, publicKey, algorithm);

            case 'ML-DSA-44':
            case 'ML-DSA-65':
            case 'ML-DSA-87':
                return verifyWithMLDSA(data, signature, publicKey, algorithm);

            case 'SLH-DSA-SHA2-192f':
                return verifyWithSLHDSA(data, signature, publicKey, algorithm);

            default:
                throw new Error(
                    `Unsupported verification algorithm: ${algorithm satisfies never}`
                );
        }
    } catch (error) {
        console.error('Signature verification failed:', error);
        return false;
    }
}

/**
 * Verifies a JWT signature using a classic algorithm.
 */
async function verifyWithClassic(
    jwt: string,
    publicKeyPem: string,
    algorithm: ClassicAlgorithm
): Promise<boolean> {
    const publicKey = await jose.importSPKI(publicKeyPem, algorithm);

    try {
        await jose.jwtVerify(jwt, publicKey);
        return true;
    } catch {
        return false;
    }
}

/**
 * Verifies a signature using ML-DSA (Dilithium) algorithm.
 */
function verifyWithMLDSA(
    data: Buffer,
    signatureBase64: string,
    publicKeyBase64: string,
    algorithm: MLDSAAlgorithm
): boolean {
    const instance = ML_DSA_INSTANCES[algorithm];
    const signature = Buffer.from(signatureBase64, 'base64');
    const publicKey = Buffer.from(publicKeyBase64, 'base64');

    return instance.verify(signature, data, publicKey);
}

/**
 * Verifies a signature using SLH-DSA (SPHINCS+) algorithm.
 */
function verifyWithSLHDSA(
    data: Buffer,
    signatureBase64: string,
    publicKeyBase64: string,
    _algorithm: SLHDSAAlgorithm
): boolean {
    const instance = SLH_DSA_INSTANCES['SLH-DSA-SHA2-192f'];
    const signature = Buffer.from(signatureBase64, 'base64');
    const publicKey = Buffer.from(publicKeyBase64, 'base64');

    return instance.verify(signature, data, publicKey);
}

// ============================================================================
// KEY ENCRYPTION (for database storage)
// ============================================================================

/**
 * Encrypts a private key for secure database storage.
 *
 * Uses AES-256-GCM authenticated encryption with a 256-bit master key.
 * The IV and authentication tag are prepended to the ciphertext.
 *
 * Storage format: `{iv}:{authTag}:{ciphertext}` (all base64-encoded)
 *
 * @param privateKey - Private key to encrypt (PEM or base64)
 * @param masterKey - 256-bit master key (32 bytes)
 * @returns Encrypted key string for signingKeys.privateKeyEncrypted
 *
 * @example
 * ```typescript
 * const masterKey = Buffer.from(process.env.MASTER_KEY!, 'base64');
 * const encrypted = await encryptPrivateKey(keyPair.privateKey, masterKey);
 * // Store in signingKeys.privateKeyEncrypted
 * ```
 *
 * @security
 * - Master key should be stored in a secure secret manager (e.g., AWS KMS, Vault)
 * - Never log or expose the master key
 * - Rotate master key periodically and re-encrypt all stored keys
 */
export async function encryptPrivateKey(
    privateKey: string,
    masterKey: Buffer
): Promise<string> {
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', masterKey, iv);

    let encrypted = cipher.update(privateKey, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    const authTag = cipher.getAuthTag();

    return `${iv.toString('base64')}:${authTag.toString('base64')}:${encrypted}`;
}

/**
 * Decrypts a private key from database storage.
 *
 * @param encryptedData - Encrypted key from signingKeys.privateKeyEncrypted
 * @param masterKey - 256-bit master key (must match encryption key)
 * @returns Decrypted private key (PEM or base64 format)
 * @throws Error if decryption fails (wrong key, tampered data, invalid format)
 *
 * @example
 * ```typescript
 * const masterKey = Buffer.from(process.env.MASTER_KEY!, 'base64');
 * const privateKey = await decryptPrivateKey(
 *   signingKey.privateKeyEncrypted,
 *   masterKey
 * );
 * ```
 */
export async function decryptPrivateKey(
    encryptedData: string,
    masterKey: Buffer
): Promise<string> {
    const parts = encryptedData.split(':');

    if (parts.length !== 3) {
        throw new Error(
            'Invalid encrypted key format: expected iv:authTag:ciphertext'
        );
    }

    const [ivBase64, authTagBase64, ciphertext] = parts;
    const iv = Buffer.from(ivBase64!, 'base64');
    const authTag = Buffer.from(authTagBase64!, 'base64');

    const decipher = createDecipheriv('aes-256-gcm', masterKey, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertext!, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

// ============================================================================
// JWT OPERATIONS
// ============================================================================

/**
 * Creates a signed JWT with the specified payload.
 *
 * For classic algorithms, uses standard jose JWT signing.
 * For post-quantum algorithms, creates a custom JWT structure with
 * post-quantum signature in the third segment.
 *
 * @param payload - JWT payload (claims)
 * @param privateKey - Private key for signing
 * @param algorithm - Signing algorithm
 * @param kid - Key identifier (included in JWT header)
 * @param expiresIn - Optional expiration duration (e.g., '1h', '7d', '15m')
 * @returns Signed JWT string
 *
 * @example
 * ```typescript
 * // Create access token
 * const accessToken = await createJWT(
 *   { sub: userId, scope: 'read write' },
 *   signingKey.privateKey,
 *   'ML-DSA-65',
 *   signingKey.kid,
 *   '15m'
 * );
 *
 * // Create refresh token (longer expiry)
 * const refreshToken = await createJWT(
 *   { sub: userId, type: 'refresh', family: tokenFamily },
 *   signingKey.privateKey,
 *   'ML-DSA-65',
 *   signingKey.kid,
 *   '7d'
 * );
 * ```
 */
export async function createJWT(
    payload: Record<string, unknown>,
    privateKey: string,
    algorithm: SigningAlgorithm,
    kid: string,
    expiresIn?: string
): Promise<string> {
    // Classic algorithms: use standard jose JWT
    if (isClassicAlgorithm(algorithm)) {
        const key = await jose.importPKCS8(privateKey, algorithm);

        const jwt = new jose.SignJWT(payload)
            .setProtectedHeader({ alg: algorithm, kid })
            .setIssuedAt();

        if (expiresIn) {
            jwt.setExpirationTime(expiresIn);
        }

        return jwt.sign(key);
    }

    // Post-quantum algorithms: custom JWT structure
    return createPostQuantumJWT(payload, privateKey, algorithm, kid, expiresIn);
}

/**
 * Type guard to check if algorithm is a classic (jose-supported) algorithm.
 */
function isClassicAlgorithm(
    algorithm: SigningAlgorithm
): algorithm is ClassicAlgorithm {
    return ['EdDSA', 'ES256', 'ES384', 'RS256'].includes(algorithm);
}

/**
 * Creates a JWT with post-quantum signature.
 * Structure: header.payload.signature (all base64url-encoded)
 */
async function createPostQuantumJWT(
    payload: Record<string, unknown>,
    privateKey: string,
    algorithm: SigningAlgorithm,
    kid: string,
    expiresIn?: string
): Promise<string> {
    const header = { alg: algorithm, kid, typ: 'JWT' };

    const now = Math.floor(Date.now() / 1000);
    const claims = {
        ...payload,
        iat: now,
        ...(expiresIn && { exp: now + parseDuration(expiresIn) }),
    };

    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(claims)).toString(
        'base64url'
    );
    const message = `${headerB64}.${payloadB64}`;

    const { signature } = await signMessage(
        message,
        privateKey,
        algorithm,
        kid
    );
    const signatureB64url = Buffer.from(signature, 'base64').toString(
        'base64url'
    );

    return `${message}.${signatureB64url}`;
}

/**
 * Parses a duration string into seconds.
 *
 * @param duration - Duration string (e.g., '15m', '1h', '7d', '2w')
 * @returns Duration in seconds
 * @throws Error if format is invalid
 *
 * Supported units:
 * - s: seconds
 * - m: minutes
 * - h: hours
 * - d: days
 * - w: weeks
 */
function parseDuration(duration: string): number {
    const match = duration.match(/^(\d+)([smhdw])$/);

    if (!match) {
        throw new Error(
            `Invalid duration format: "${duration}". Expected format: number + unit (s/m/h/d/w)`
        );
    }

    const [, value, unit] = match;
    return parseInt(value!, 10) * DURATION_UNITS[unit!]!;
}

// ============================================================================
// JWKS EXPORT (for public key distribution)
// ============================================================================

/**
 * Exports a public key to JWK format for JWKS endpoint.
 *
 * For classic algorithms, uses standard JWK format.
 * For post-quantum algorithms, uses emerging PQC JWK format:
 * - ML-DSA: kty="PQC", crv="ML-DSA-XX", pk=base64url(publicKey)
 * - SLH-DSA: kty="SPHINCS+", crv="SLH-DSA-SHA2-192f", pk=base64url(publicKey)
 *
 * @param publicKey - Public key to export
 * @param algorithm - Algorithm for this key
 * @param kid - Key identifier
 * @returns JWK object for inclusion in JWKS
 *
 * @example
 * ```typescript
 * const jwk = await exportToJWK(
 *   signingKey.publicKey,
 *   signingKey.algorithm,
 *   signingKey.kid
 * );
 * // Add to JWKS endpoint response
 * ```
 */
export async function exportToJWK(
    publicKey: string,
    algorithm: SigningAlgorithm,
    kid: string
): Promise<jose.JWK> {
    // Classic algorithms: standard JWK export
    if (isClassicAlgorithm(algorithm)) {
        const key = await jose.importSPKI(publicKey, algorithm);
        const jwk = await jose.exportJWK(key);

        return {
            ...jwk,
            kid,
            alg: algorithm,
            use: 'sig',
        };
    }

    // ML-DSA algorithms: PQC JWK format
    if (algorithm.startsWith('ML-DSA-')) {
        const pkBase64url = Buffer.from(publicKey, 'base64').toString(
            'base64url'
        );

        return {
            kty: 'PQC',
            crv: algorithm,
            pk: pkBase64url,
            alg: algorithm,
            kid,
            use: 'sig',
        } as jose.JWK;
    }

    // SLH-DSA algorithms: SPHINCS+ JWK format
    if (algorithm.startsWith('SLH-DSA-')) {
        const pkBase64url = Buffer.from(publicKey, 'base64').toString(
            'base64url'
        );

        return {
            kty: 'SPHINCS+',
            crv: algorithm,
            pk: pkBase64url,
            alg: algorithm,
            kid,
            use: 'sig',
        } as jose.JWK;
    }

    // Fallback (should never reach here due to type safety)
    throw new Error(`Unsupported algorithm for JWK export: ${algorithm}`);
}

/**
 * Creates a complete JWKS (JSON Web Key Set) from multiple keys.
 *
 * Use this to build the /.well-known/jwks.json endpoint response.
 *
 * @param keys - Array of key metadata objects
 * @returns JWKS object with all public keys
 *
 * @example
 * ```typescript
 * // Fetch active signing keys from database
 * const activeKeys = await db.query.signingKeys.findMany({
 *   where: eq(signingKeys.isActive, true)
 * });
 *
 * // Build JWKS response
 * const jwks = await createJWKS(activeKeys.map(k => ({
 *   publicKey: k.publicKey,
 *   algorithm: k.algorithm,
 *   kid: k.kid
 * })));
 *
 * // Return as JSON response
 * return Response.json(jwks);
 * ```
 */
export async function createJWKS(
    keys: Array<{
        publicKey: string;
        algorithm: SigningAlgorithm;
        kid: string;
    }>
): Promise<{ keys: jose.JWK[] }> {
    const jwks = await Promise.all(
        keys.map((key) => exportToJWK(key.publicKey, key.algorithm, key.kid))
    );

    return { keys: jwks };
}
