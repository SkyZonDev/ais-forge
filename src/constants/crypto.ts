/**
 * @fileoverview Cryptographic constants and algorithm instances.
 * @module utils/crypto/constants
 */

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
    slh_dsa_sha2_192f,
    slh_dsa_shake_192f,
} from '@noble/post-quantum/slh-dsa.js';

import type { ClassicAlgorithm, SigningAlgorithm } from '../types/crypto';

// ============================================================================
// POST-QUANTUM ALGORITHM INSTANCES
// ============================================================================

/**
 * ML-DSA (Dilithium) algorithm instances mapped by algorithm name.
 * @see NIST FIPS 204
 */
export const ML_DSA_INSTANCES = {
    'ML-DSA-44': ml_dsa44,
    'ML-DSA-65': ml_dsa65,
    'ML-DSA-87': ml_dsa87,
} as const;

/**
 * SLH-DSA (SPHINCS+) algorithm instances mapped by algorithm name.
 * @see NIST FIPS 205
 */
export const SLH_DSA_INSTANCES = {
    'SLH-DSA-SHA2-192f': slh_dsa_sha2_192f,
    'SLH-DSA-SHAKE-192f': slh_dsa_shake_192f,
} as const;

// ============================================================================
// DURATION PARSING
// ============================================================================

/**
 * Duration units in seconds for JWT expiration parsing.
 */
export const DURATION_UNITS: Record<string, number> = {
    s: 1,
    m: 60,
    h: 3600,
    d: 86400,
    w: 604800,
};

/**
 * Parses a duration string into seconds.
 *
 * @param duration - Duration string (e.g., '15m', '1h', '7d', '2w')
 * @returns Duration in seconds
 * @throws Error if format is invalid
 *
 * @example
 * ```typescript
 * parseDuration('15m'); // 900
 * parseDuration('1h');  // 3600
 * parseDuration('7d');  // 604800
 * ```
 */
export function parseDuration(duration: string): number {
    const match = duration.match(/^(\d+)([smhdw])$/);

    if (!match) {
        throw new Error(
            `Invalid duration format: "${duration}". Expected format: number + unit (s/m/h/d/w)`
        );
    }

    const [, value, unit] = match;
    return parseInt(value!, 10) * DURATION_UNITS[unit!]!;
}

// ============================================================================
// ALGORITHM TYPE GUARDS
// ============================================================================

/** Classic algorithms array for type checking */
export const CLASSIC_ALGORITHMS: ClassicAlgorithm[] = [
    'EdDSA',
    'ES256',
    'ES384',
    'RS256',
];

/**
 * Type guard to check if algorithm is a classic (jose-supported) algorithm.
 *
 * @param algorithm - Algorithm to check
 * @returns True if algorithm is classic (EdDSA, ES256, ES384, RS256)
 */
export function isClassicAlgorithm(
    algorithm: SigningAlgorithm
): algorithm is ClassicAlgorithm {
    return CLASSIC_ALGORITHMS.includes(algorithm as ClassicAlgorithm);
}

/**
 * Type guard to check if algorithm is ML-DSA (Dilithium).
 *
 * @param algorithm - Algorithm to check
 * @returns True if algorithm is ML-DSA-44, ML-DSA-65, or ML-DSA-87
 */
export function isMLDSAAlgorithm(
    algorithm: SigningAlgorithm
): algorithm is 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87' {
    return algorithm.startsWith('ML-DSA-');
}

/**
 * Type guard to check if algorithm is SLH-DSA (SPHINCS+).
 *
 * @param algorithm - Algorithm to check
 * @returns True if algorithm is SLH-DSA variant
 */
export function isSLHDSAAlgorithm(
    algorithm: SigningAlgorithm
): algorithm is 'SLH-DSA-SHA2-192f' {
    return algorithm.startsWith('SLH-DSA-');
}
