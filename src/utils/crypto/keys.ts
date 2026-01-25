/**
 * @fileoverview Cryptographic key generation for classic and post-quantum algorithms.
 * @module utils/crypto/keys
 */

import { randomBytes } from 'node:crypto';
import * as jose from 'jose';

import { ML_DSA_INSTANCES, SLH_DSA_INSTANCES } from '../../constants/crypto';
import type {
    KeyPair,
    MLDSAAlgorithm,
    SigningAlgorithm,
    SLHDSAAlgorithm,
} from '../../types/crypto';

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
export function generateKid(): string {
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
    const { publicKey, privateKey } = await jose.generateKeyPair(algorithm, {
        extractable: true,
    });

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
