import * as schema from '../db';
import type { CursorPaginationOptions } from './pagination';

type RefreshToken = typeof schema.refreshTokens.$inferSelect;
type RefreshTokenInsert = typeof schema.refreshTokens.$inferInsert;

interface RefreshTokenPaginationOptions extends CursorPaginationOptions {
    /** Whether to include revoked refresh token (default: false) */
    includeRevoked?: boolean;
    /** Whether to include expired refresh token (default: false) */
    includeUsed?: boolean;
}
interface RefreshTokenStats {
    /** Total number of auth refresh token */
    total: number;
    /** Number of active (non-revoked, non-expired) refresh token */
    active: number;
    /** Number of revoked refresh token */
    revoked: number;
    /** Number of used refresh token */
    used: number;
    /** Number of expired refresh token */
    expired: number;
    /** Number of stolen refresh token */
    stolen: number;
}

export type {
    RefreshToken,
    RefreshTokenInsert,
    RefreshTokenPaginationOptions,
    RefreshTokenStats,
};
