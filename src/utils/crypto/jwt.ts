/**
 * @fileoverview JWT creation and verification for classic and post-quantum algorithms.
 * @module utils/crypto/jwt
 */

import * as jose from 'jose';

import {
    isClassicAlgorithm,
    isMLDSAAlgorithm,
    isSLHDSAAlgorithm,
    ML_DSA_INSTANCES,
    parseDuration,
    SLH_DSA_INSTANCES,
} from '../../constants/crypto';
import type {
    ClassicAlgorithm,
    JWTClaims,
    JWTHeader,
    JWTVerifyOptions,
    JWTVerifyResult,
    MLDSAAlgorithm,
    SigningAlgorithm,
    SLHDSAAlgorithm,
} from '../../types/crypto';
import { JWTVerificationError } from '../../types/crypto';
import { signMessage } from './signing.js';

// ============================================================================
// JWT CREATION
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

// ============================================================================
// JWT VERIFICATION
// ============================================================================

/**
 * Verifies a JWT and returns the decoded payload.
 *
 * Supports both classic (EdDSA, ECDSA, RSA) and post-quantum (ML-DSA, SLH-DSA)
 * algorithms. Validates signature, expiration, and optional claims.
 *
 * @param token - JWT string to verify
 * @param publicKey - Public key in PEM (classic) or base64 (post-quantum)
 * @param algorithm - Expected signing algorithm
 * @param options - Optional verification options
 * @returns Verified JWT header and payload
 * @throws JWTVerificationError if verification fails
 *
 * @example
 * ```typescript
 * try {
 *   const { payload } = await verifyJWT(
 *     token,
 *     signingKey.publicKey,
 *     'ML-DSA-65',
 *     { issuer: 'ais-forge', audience: 'api' }
 *   );
 *   console.log('User ID:', payload.sub);
 * } catch (error) {
 *   if (error instanceof JWTVerificationError) {
 *     console.error('JWT error:', error.code, error.message);
 *   }
 * }
 * ```
 */
export async function verifyJWT(
    token: string,
    publicKey: string,
    algorithm: SigningAlgorithm,
    options: JWTVerifyOptions = {}
): Promise<JWTVerifyResult> {
    // Parse token structure
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new JWTVerificationError(
            'Invalid JWT format: expected 3 parts separated by dots',
            'INVALID_TOKEN_FORMAT'
        );
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Decode and validate header
    const header = decodeJWTHeader(headerB64!);
    if (header.alg !== algorithm) {
        throw new JWTVerificationError(
            `Algorithm mismatch: expected ${algorithm}, got ${header.alg}`,
            'ALGORITHM_MISMATCH'
        );
    }

    // Decode payload
    const payload = decodeJWTPayload(payloadB64!);

    // Verify signature
    const isValid = await verifyJWTSignature(
        `${headerB64}.${payloadB64}`,
        signatureB64!,
        publicKey,
        algorithm
    );

    if (!isValid) {
        throw new JWTVerificationError(
            'Invalid signature',
            'INVALID_SIGNATURE'
        );
    }

    // Validate claims
    validateClaims(payload, options);

    return { header, payload };
}

/**
 * Decodes and validates JWT header.
 */
function decodeJWTHeader(headerB64: string): JWTHeader {
    try {
        const decoded = Buffer.from(headerB64, 'base64url').toString('utf8');
        const header = JSON.parse(decoded);

        if (!header.alg || typeof header.alg !== 'string') {
            throw new Error('Missing or invalid "alg" claim');
        }

        return header as JWTHeader;
    } catch (error) {
        throw new JWTVerificationError(
            'Failed to decode JWT header',
            'INVALID_HEADER',
            error
        );
    }
}

/**
 * Decodes JWT payload.
 */
function decodeJWTPayload(payloadB64: string): JWTClaims {
    try {
        const decoded = Buffer.from(payloadB64, 'base64url').toString('utf8');
        return JSON.parse(decoded) as JWTClaims;
    } catch (error) {
        throw new JWTVerificationError(
            'Failed to decode JWT payload',
            'INVALID_PAYLOAD',
            error
        );
    }
}

/**
 * Verifies JWT signature using appropriate algorithm.
 */
async function verifyJWTSignature(
    message: string,
    signatureB64url: string,
    publicKey: string,
    algorithm: SigningAlgorithm
): Promise<boolean> {
    try {
        if (isClassicAlgorithm(algorithm)) {
            return await verifyClassicJWTSignature(
                message,
                signatureB64url,
                publicKey,
                algorithm
            );
        }

        if (isMLDSAAlgorithm(algorithm)) {
            return verifyMLDSAJWTSignature(
                message,
                signatureB64url,
                publicKey,
                algorithm
            );
        }

        if (isSLHDSAAlgorithm(algorithm)) {
            return verifySLHDSAJWTSignature(
                message,
                signatureB64url,
                publicKey,
                algorithm
            );
        }

        return false;
    } catch {
        return false;
    }
}

/**
 * Verifies JWT signature using classic (jose) algorithm.
 */
async function verifyClassicJWTSignature(
    _message: string,
    signatureB64url: string,
    publicKeyPem: string,
    algorithm: ClassicAlgorithm
): Promise<boolean> {
    // For classic algorithms, we need to verify the complete JWT
    // Reconstruct the full JWT for jose verification
    const key = await jose.importSPKI(publicKeyPem, algorithm);

    try {
        // Create a minimal verifier - jose handles the signature verification
        const fullJwt = `${_message}.${signatureB64url}`;
        await jose.jwtVerify(fullJwt, key, {
            algorithms: [algorithm],
        });
        return true;
    } catch {
        return false;
    }
}

/**
 * Verifies JWT signature using ML-DSA (Dilithium).
 */
function verifyMLDSAJWTSignature(
    message: string,
    signatureB64url: string,
    publicKeyBase64: string,
    algorithm: MLDSAAlgorithm
): boolean {
    const instance = ML_DSA_INSTANCES[algorithm];
    const signatureBytes = Buffer.from(signatureB64url, 'base64url');
    const publicKeyBytes = Buffer.from(publicKeyBase64, 'base64');
    const messageBytes = Buffer.from(message, 'utf8');

    return instance.verify(signatureBytes, messageBytes, publicKeyBytes);
}

/**
 * Verifies JWT signature using SLH-DSA (SPHINCS+).
 */
function verifySLHDSAJWTSignature(
    message: string,
    signatureB64url: string,
    publicKeyBase64: string,
    _algorithm: SLHDSAAlgorithm
): boolean {
    const instance = SLH_DSA_INSTANCES['SLH-DSA-SHA2-192f'];
    const signatureBytes = Buffer.from(signatureB64url, 'base64url');
    const publicKeyBytes = Buffer.from(publicKeyBase64, 'base64');
    const messageBytes = Buffer.from(message, 'utf8');

    return instance.verify(signatureBytes, messageBytes, publicKeyBytes);
}

/**
 * Validates JWT claims against options.
 */
function validateClaims(payload: JWTClaims, options: JWTVerifyOptions): void {
    const now = Math.floor(Date.now() / 1000);
    const clockTolerance = options.clockTolerance ?? 0;

    // Check expiration
    if (!options.ignoreExpiration && payload.exp !== undefined) {
        if (now > payload.exp + clockTolerance) {
            throw new JWTVerificationError(
                `Token expired at ${new Date(payload.exp * 1000).toISOString()}`,
                'TOKEN_EXPIRED'
            );
        }
    }

    // Check not before
    if (payload.nbf !== undefined) {
        if (now < payload.nbf - clockTolerance) {
            throw new JWTVerificationError(
                `Token not valid before ${new Date(payload.nbf * 1000).toISOString()}`,
                'TOKEN_NOT_YET_VALID'
            );
        }
    }

    // Check issuer
    if (options.issuer !== undefined) {
        if (payload.iss !== options.issuer) {
            throw new JWTVerificationError(
                `Invalid issuer: expected "${options.issuer}", got "${payload.iss}"`,
                'INVALID_ISSUER'
            );
        }
    }

    // Check audience
    if (options.audience !== undefined) {
        const expectedAudiences = Array.isArray(options.audience)
            ? options.audience
            : [options.audience];

        const tokenAudiences = Array.isArray(payload.aud)
            ? payload.aud
            : payload.aud
              ? [payload.aud]
              : [];

        const hasValidAudience = expectedAudiences.some((expected) =>
            tokenAudiences.includes(expected)
        );

        if (!hasValidAudience) {
            throw new JWTVerificationError(
                `Invalid audience: expected one of [${expectedAudiences.join(', ')}], got [${tokenAudiences.join(', ')}]`,
                'INVALID_AUDIENCE'
            );
        }
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Decodes a JWT without verifying the signature.
 *
 * ⚠️ WARNING: Only use for debugging or when signature verification
 * is handled separately. Never trust unverified tokens for authorization.
 *
 * @param token - JWT string to decode
 * @returns Decoded header and payload
 * @throws JWTVerificationError if token format is invalid
 *
 * @example
 * ```typescript
 * // Inspect token claims (e.g., to determine which key to use)
 * const { header, payload } = decodeJWT(token);
 * console.log('Token algorithm:', header.alg);
 * console.log('Token kid:', header.kid);
 * console.log('Token expires:', new Date(payload.exp! * 1000));
 * ```
 */
export function decodeJWT(token: string): JWTVerifyResult {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new JWTVerificationError(
            'Invalid JWT format: expected 3 parts separated by dots',
            'INVALID_TOKEN_FORMAT'
        );
    }

    const header = decodeJWTHeader(parts[0]!);
    const payload = decodeJWTPayload(parts[1]!);

    return { header, payload };
}

/**
 * Checks if a JWT is expired without full verification.
 *
 * @param token - JWT string to check
 * @param clockTolerance - Clock tolerance in seconds (default: 0)
 * @returns True if token is expired or has no exp claim
 *
 * @example
 * ```typescript
 * if (isJWTExpired(accessToken)) {
 *   // Refresh the token
 *   accessToken = await refreshAccessToken(refreshToken);
 * }
 * ```
 */
export function isJWTExpired(token: string, clockTolerance = 0): boolean {
    try {
        const { payload } = decodeJWT(token);
        if (payload.exp === undefined) {
            return true; // No expiration = expired
        }
        const now = Math.floor(Date.now() / 1000);
        return now > payload.exp + clockTolerance;
    } catch {
        return true; // Invalid token = expired
    }
}

/**
 * Extracts the key ID (kid) from a JWT header without verification.
 *
 * Useful for determining which key to use for verification in a JWKS scenario.
 *
 * @param token - JWT string
 * @returns Key ID if present, undefined otherwise
 *
 * @example
 * ```typescript
 * const kid = getJWTKeyId(token);
 * const signingKey = await signingKeyRepository.findByKid(kid);
 * const result = await verifyJWT(token, signingKey.publicKey, signingKey.algorithm);
 * ```
 */
export function getJWTKeyId(token: string): string | undefined {
    try {
        const { header } = decodeJWT(token);
        return header.kid;
    } catch {
        return undefined;
    }
}
