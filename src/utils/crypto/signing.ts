/**
 * @fileoverview Digital signature operations for classic and post-quantum algorithms.
 * @module utils/crypto/signing
 */

import * as jose from 'jose';

import { ML_DSA_INSTANCES, SLH_DSA_INSTANCES } from '../../constants/crypto';
import type {
    ClassicAlgorithm,
    MLDSAAlgorithm,
    SignatureResult,
    SigningAlgorithm,
    SLHDSAAlgorithm,
} from '../../types/crypto';

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

// ============================================================================
// CLASSIC SIGNING (EdDSA, ECDSA, RSA)
// ============================================================================

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

// ============================================================================
// POST-QUANTUM SIGNING (ML-DSA, SLH-DSA)
// ============================================================================

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

// ============================================================================
// CLASSIC VERIFICATION
// ============================================================================

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

// ============================================================================
// POST-QUANTUM VERIFICATION
// ============================================================================

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
