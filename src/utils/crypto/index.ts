/**
 * @fileoverview Cryptographic utilities for AIS Forge authentication system.
 *
 * This module provides a comprehensive cryptographic toolkit supporting
 * both classic (EdDSA, ECDSA, RSA) and post-quantum (ML-DSA, SLH-DSA)
 * algorithms for digital signatures and JWT operations.
 *
 * @module utils/crypto
 *
 * @example
 * ```typescript
 * import {
 *   // Key generation
 *   generateKeyPair,
 *   generateKid,
 *
 *   // Password hashing
 *   hashPassword,
 *   verifyPassword,
 *
 *   // JWT operations
 *   createJWT,
 *   verifyJWT,
 *   decodeJWT,
 *   isJWTExpired,
 *   getJWTKeyId,
 *
 *   // Signing
 *   signMessage,
 *   verifySignature,
 *
 *   // Encryption
 *   encryptPrivateKey,
 *   decryptPrivateKey,
 *   generateMasterKey,
 *
 *   // JWKS
 *   exportToJWK,
 *   createJWKS,
 *
 *   // Types
 *   type SigningAlgorithm,
 *   type KeyPair,
 *   type JWTClaims,
 *   JWTVerificationError,
 * } from '@/utils/crypto';
 * ```
 */

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

export type {
    EncryptedKeyPair,
    JWTClaims,
    JWTErrorCode,
    JWTHeader,
    JWTVerifyOptions,
    JWTVerifyResult,
    KeyPair,
    SignatureResult,
    SigningAlgorithm,
} from '../../types/crypto';

export { JWTVerificationError } from '../../types/crypto';

// ============================================================================
// CONSTANTS & UTILITIES
// ============================================================================

export {
    DURATION_UNITS,
    parseDuration,
} from '../../constants/crypto';

// ============================================================================
// PASSWORD HASHING
// ============================================================================

export { hashPassword, verifyPassword } from './password.js';

// ============================================================================
// SIGNING OPERATIONS
// ============================================================================

export { signMessage, verifySignature } from './signing.js';

// ============================================================================
// ENCRYPTION
// ============================================================================

export {
    decryptPrivateKey,
    encryptPrivateKey,
    generateMasterKey,
} from './encryption.js';

// ============================================================================
// JWT OPERATIONS
// ============================================================================

export {
    createJWT,
    decodeJWT,
    getJWTKeyId,
    isJWTExpired,
    verifyJWT,
} from './jwt.js';

// ============================================================================
// JWKS
// ============================================================================

export { createJWKS, exportToJWK, importFromJWK } from './jwks.js';
