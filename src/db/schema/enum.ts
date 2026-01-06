import { pgEnum } from 'drizzle-orm/pg-core';

// ============================================================================
// IDENTITY ENUMS
// ============================================================================

export const identityTypeEnum = pgEnum('identity_type', [
    'human',
    'service',
    'machine',
]);
export const identityStatusEnum = pgEnum('identity_status', [
    'active',
    'suspended',
    'deleted',
]);

// ============================================================================
// AUTHENTICATION ENUMS
// ============================================================================

export const authMethodTypeEnum = pgEnum('auth_method_type', [
    'password',
    'pat',
    'api_key',
]);

// Revocation reasons for traceability
export const revokedReasonEnum = pgEnum('revoked_reason', [
    'used', // Normal token used then rotated
    'stolen', // Theft detection (reuse)
    'manual', // Manual revocation by user
    'family_revoked', // Entire token family revoked
    'expired', // Automatically expired
    'logout', // Voluntary logout
]);

// ============================================================================
// SIGNING KEY ENUMS
// ============================================================================

export const signingAlgorithmEnum = pgEnum('signing_algorithm', [
    // Classic (current production)
    'EdDSA', // Ed25519 - Fast, modern
    'ES384', // ECDSA P-384 - Industry standard
    'ES256', // ECDSA P-256 - Widely supported

    // Post-quantum FIPS (2025+)
    'ML-DSA-65', // Dilithium3 - NIST Cat-3 recommended
    'ML-DSA-87', // Dilithium5 - High security Cat-5
    'ML-DSA-44', // Dilithium2 - Lightweight (if needed)

    // Hash-based (ultra conservative)
    'SLH-DSA-SHA2-192f', // SPHINCS+ - Slow but quantum-safe

    // Legacy
    'RS256', // RSA - Compatibility (<2030)
]);

// ============================================================================
// AUDIT ENUMS
// ============================================================================

export const eventCategoryEnum = pgEnum('event_category', [
    'auth', // Authentication
    'permission', // Permission changes
    'admin', // Administrative actions
    'security', // Security events
    'identity', // Identity management
    'token', // Token operations
]);

export const eventSeverityEnum = pgEnum('event_severity', [
    'debug', // Debugging only
    'info', // Normal information
    'warning', // Attention required
    'error', // Non-critical error
    'critical', // Security incident
]);
