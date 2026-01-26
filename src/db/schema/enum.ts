import { pgEnum } from 'drizzle-orm/pg-core';

// ============================================================================
// IDENTITY ENUMS
// ============================================================================
export const identityType = ['human', 'service', 'machine'] as const;

export const identityTypeEnum = pgEnum('identity_type', identityType);

export const identityStatus = ['active', 'suspended', 'deleted'] as const;

export const identityStatusEnum = pgEnum('identity_status', identityStatus);

// ============================================================================
// AUTHENTICATION ENUMS
// ============================================================================
export const authMethodType = ['password', 'pat', 'api_key'] as const;

export const authMethodTypeEnum = pgEnum('auth_method_type', authMethodType);

// Revocation reasons for traceability
export const revokedReason = [
    'used', // Normal token used then rotated
    'stolen', // Theft detection (reuse)
    'manual', // Manual revocation by user
    'family_revoked', // Entire token family revoked
    'expired', // Automatically expired
    'logout', // Voluntary logout
] as const;

export const revokedReasonEnum = pgEnum('revoked_reason', revokedReason);

// ============================================================================
// SIGNING KEY ENUMS
// ============================================================================
export const signingAlgorithm = [
    // Classic (current production)
    'EdDSA', // Ed25519 - Fast, modern
    'ES384', // ECDSA P-384 - Industry standard
    'ES256', // ECDSA P-256 - Widely supported
    'ES512',

    // Legacy
    'RS256', // RSA - Compatibility (<2030)
] as const;

export const signingAlgorithmEnum = pgEnum(
    'signing_algorithm',
    signingAlgorithm
);

// ============================================================================
// AUDIT ENUMS
// ============================================================================

export const eventCategory = [
    'auth', // Authentication
    'permission', // Permission changes
    'admin', // Administrative actions
    'security', // Security events
    'identity', // Identity management
    'token', // Token operations
] as const;

export const eventCategoryEnum = pgEnum('event_category', eventCategory);

export const eventSeverity = [
    'debug', // Debugging only
    'info', // Normal information
    'warning', // Attention required
    'error', // Non-critical error
    'critical', // Security incident
] as const;

export const eventSeverityEnum = pgEnum('event_severity', eventSeverity);
