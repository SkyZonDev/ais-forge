/**
 * @fileoverview Digital signature operations for classic and post-quantum algorithms.
 * @module utils/crypto/signing
 */

import * as jose from 'jose';

import type { SignatureResult, SigningAlgorithm } from '../../types/crypto';

// ============================================================================
// SIGNING OPERATIONS
// ============================================================================

/**
 * Signs a message using the specified algorithm and private key.
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
 *   'ES256',
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
            return sign(data, privateKey, algorithm, kid);

        default:
            throw new Error(
                `Unsupported signing algorithm: ${algorithm satisfies never}`
            );
    }
}

// ============================================================================
// CLASSIC SIGNING (EdDSA, ECDSA, RSA)
// ============================================================================

/**
 * Signs data using a classic algorithm via jose library.
 * Returns a JWT with the data embedded in the payload.
 */
async function sign(
    data: Buffer,
    privateKeyPem: string,
    algorithm: SigningAlgorithm,
    kid: string
): Promise<SignatureResult> {
    const privateKey = await jose.importPKCS8(privateKeyPem, algorithm);

    const jwt = await new jose.SignJWT({ data: data.toString('base64') })
        .setProtectedHeader({ alg: algorithm, kid })
        .setIssuedAt()
        .sign(privateKey);

    return { signature: jwt, algorithm, kid };
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

/**
 * Verifies a digital signature against the original message.
 *
 * @param message - Original message that was signed
 * @param signature - Signature to verify (JWT or base64)
 * @param publicKey - Public key in PEM
 * @param algorithm - Algorithm used for signing
 * @returns True if signature is valid, false otherwise
 *
 * @example
 * ```typescript
 * const isValid = await verifySignature(
 *   originalMessage,
 *   signatureResult.signature,
 *   keyPair.publicKey,
 *   'ES256'
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
    try {
        switch (algorithm) {
            case 'EdDSA':
            case 'ES256':
            case 'ES384':
            case 'RS256':
                return await verify(signature, publicKey, algorithm);

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

// ============================================================================
// CLASSIC VERIFICATION
// ============================================================================

/**
 * Verifies a JWT signature using a classic algorithm.
 */
async function verify(
    jwt: string,
    publicKeyPem: string,
    algorithm: SigningAlgorithm
): Promise<boolean> {
    const publicKey = await jose.importSPKI(publicKeyPem, algorithm);

    try {
        await jose.jwtVerify(jwt, publicKey);
        return true;
    } catch {
        return false;
    }
}
