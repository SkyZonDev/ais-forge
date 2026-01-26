/**
 * @fileoverview Cryptographic constants and algorithm instances.
 * @module utils/crypto/constants
 */
import type { SigningAlgorithm } from '../types/crypto';

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
