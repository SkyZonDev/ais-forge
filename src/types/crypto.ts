/**
 * @fileoverview Cryptographic types and interfaces for AIS Forge.
 * @module utils/crypto/types
 */

// ============================================================================
// ALGORITHM TYPES
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
export type SigningAlgorithm = 'EdDSA' | 'ES256' | 'ES384' | 'RS256';

// ============================================================================
// KEY INTERFACES
// ============================================================================

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
// SIGNATURE INTERFACES
// ============================================================================

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

// ============================================================================
// JWT INTERFACES
// ============================================================================

/**
 * JWT header structure.
 */
export interface JWTHeader {
    /** Algorithm used for signing */
    alg: SigningAlgorithm;
    /** Key identifier */
    kid: string;
    /** Token type (always 'JWT') */
    typ?: string;
}

/**
 * Standard JWT claims.
 */
export interface JWTClaims {
    /** Subject (user ID) */
    sub?: string;
    /** Issuer */
    iss?: string;
    /** Audience */
    aud?: string | string[];
    /** Expiration time (Unix timestamp) */
    exp?: number;
    /** Issued at (Unix timestamp) */
    iat?: number;
    /** Not before (Unix timestamp) */
    nbf?: number;
    /** JWT ID */
    jti?: string;
    /** Custom claims */
    [key: string]: unknown;
}

/**
 * Result of a successful JWT verification.
 */
export interface JWTVerifyResult {
    /** Decoded JWT header */
    header: JWTHeader;
    /** Decoded and validated JWT payload/claims */
    payload: JWTClaims;
}

/**
 * JWT verification options.
 */
export interface JWTVerifyOptions {
    /** Expected issuer (validates 'iss' claim) */
    issuer?: string;
    /** Expected audience (validates 'aud' claim) */
    audience?: string | string[];
    /** Clock tolerance in seconds for exp/nbf validation */
    clockTolerance?: number;
    /** If true, allows expired tokens (for debugging only) */
    ignoreExpiration?: boolean;
}

// ============================================================================
// ERROR TYPES
// ============================================================================

/**
 * JWT verification error codes.
 */
export type JWTErrorCode =
    | 'INVALID_TOKEN_FORMAT'
    | 'INVALID_HEADER'
    | 'INVALID_PAYLOAD'
    | 'INVALID_SIGNATURE'
    | 'TOKEN_EXPIRED'
    | 'TOKEN_NOT_YET_VALID'
    | 'INVALID_ISSUER'
    | 'INVALID_AUDIENCE'
    | 'ALGORITHM_MISMATCH'
    | 'KEY_NOT_FOUND';

/**
 * Custom error class for JWT verification failures.
 */
export class JWTVerificationError extends Error {
    constructor(
        message: string,
        public readonly code: JWTErrorCode,
        public readonly cause?: unknown
    ) {
        super(message);
        this.name = 'JWTVerificationError';
    }
}
