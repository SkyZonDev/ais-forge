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

// Raisons de révocation pour traçabilité
export const revokedReasonEnum = pgEnum('revoked_reason', [
    'used', // Token normal utilisé puis roté
    'stolen', // Détection de vol (réutilisation)
    'manual', // Révocation manuelle par l'utilisateur
    'family_revoked', // Toute la famille de tokens révoquée
    'expired', // Expiré automatiquement
    'logout', // Déconnexion volontaire
]);

// ============================================================================
// SIGNING KEY ENUMS
// ============================================================================

export const signingAlgorithmEnum = pgEnum('signing_algorithm', [
    // Classiques (production actuelle)
    'EdDSA', // Ed25519 - Rapide, moderne
    'ES384', // ECDSA P-384 - Standard industrie
    'ES256', // ECDSA P-256 - Largement supporté

    // Post-quantique FIPS (2025+)
    'ML-DSA-65', // Dilithium3 - Recommandé NIST Cat-3
    'ML-DSA-87', // Dilithium5 - Haute sécurité Cat-5
    'ML-DSA-44', // Dilithium2 - Léger (si besoin)

    // Hash-based (ultra conservatif)
    'SLH-DSA-SHA2-192f', // SPHINCS+ - Lent mais quantum-safe

    // Legacy
    'RS256', // RSA - Compatibilité (<2030)
]);

// ============================================================================
// AUDIT ENUMS
// ============================================================================

export const eventCategoryEnum = pgEnum('event_category', [
    'auth', // Authentification
    'permission', // Changements de permissions
    'admin', // Actions administratives
    'security', // Événements de sécurité
    'identity', // Gestion des identités
    'token', // Opérations sur les tokens
]);

export const eventSeverityEnum = pgEnum('event_severity', [
    'debug', // Debugging uniquement
    'info', // Information normale
    'warning', // Attention requise
    'error', // Erreur non-critique
    'critical', // Incident de sécurité
]);
