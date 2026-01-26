/**
 * @fileoverview Private key encryption utilities using AES-256-GCM.
 * @module utils/crypto/encryption
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

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
    if (masterKey.length !== 32) {
        throw new Error(
            `Master key must be exactly 32 bytes (256 bits), got ${masterKey.length} bytes`
        );
    }

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
    if (masterKey.length !== 32) {
        throw new Error(
            `Master key must be exactly 32 bytes (256 bits), got ${masterKey.length} bytes`
        );
    }

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

/**
 * Generates a new 256-bit master key for encryption.
 *
 * @returns Master key as a Buffer (32 bytes)
 *
 * @example
 * ```typescript
 * const masterKey = generateMasterKey();
 * console.log('MASTER_KEY=' + masterKey.toString('base64'));
 * ```
 *
 * @security
 * - Store securely in environment variables or secret manager
 * - Never commit to version control
 * - Backup securely - loss means data is unrecoverable
 */
export function generateMasterKey(): Buffer {
    return randomBytes(32);
}
