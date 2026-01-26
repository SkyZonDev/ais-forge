/**
 * @fileoverview Password hashing utilities using Argon2id.
 * @module utils/crypto/password
 */

import { createHash } from 'node:crypto';
import { hash, verify } from '@node-rs/argon2';

/**
 * Hash a token with SHA-256 (deterministic)
 * Use this for tokens, NOT passwords!
 */
export function hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
}

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
