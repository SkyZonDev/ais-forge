/**
 * @fileoverview JWKS (JSON Web Key Set) export utilities.
 * @module utils/crypto/jwks
 */

import * as jose from 'jose';

import { isClassicAlgorithm } from '../../constants/crypto';
import type { SigningAlgorithm } from '../../types/crypto';
import {base64url} from "jose";

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
            pub: pkBase64url,
            alg: algorithm,
            kid,
            use: 'sig',
        };
    }

    // SLH-DSA algorithms: SPHINCS+ JWK format
    if (algorithm.startsWith('SLH-DSA-')) {
        const pkBase64url = Buffer.from(publicKey, 'base64').toString(
            'base64url'
        );

        return {
            kty: 'SPHINCS+',
            crv: algorithm,
            pub: pkBase64url,
            alg: algorithm,
            kid,
            use: 'sig',
        };
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

/**
 * Imports a JWK and returns the corresponding KeyLike object for jose.
 *
 * Only supports classic algorithms. Post-quantum keys must be handled
 * using the raw base64 format.
 *
 * @param jwk - JWK object to import
 * @returns KeyLike object for jose operations
 * @throws Error if algorithm is not supported or JWK is invalid
 *
 * @example
 * ```typescript
 * const response = await fetch('https://auth.example.com/.well-known/jwks.json');
 * const jwks = await response.json();
 * const key = await importFromJWK(jwks.keys[0]);
 * ```
 */
export async function importFromJWK(
    jwk: jose.JWK
): Promise<jose.CryptoKey | Uint8Array> {
    const alg = jwk.alg;

    if (!alg) {
        throw new Error('JWK must have an "alg" property');
    }

    // Check for post-quantum algorithms
    if (jwk.kty === 'PQC' || jwk.kty === 'SPHINCS+') {
        return base64url.decode(jwk.pub!)
    }

    return jose.importJWK(jwk, alg);
}
