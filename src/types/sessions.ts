import * as schema from '../db';
import type { CursorPaginationOptions } from './pagination';

type Session = typeof schema.sessions.$inferSelect;
type SessionInsert = typeof schema.sessions.$inferInsert;

interface SessionPaginationOptions extends CursorPaginationOptions {
    /** Whether to include revoked sessions (default: false) */
    includeRevoked?: boolean;
}
interface SessionStats {
    /** Total number of auth sessions */
    total: number;
    /** Number of active (non-revoked, non-expired) sessions */
    active: number;
    /** Number of revoked sessions */
    revoked: number;
    /** Number of expired sessions */
    expired: number;
}

interface UpdateMetadataOptions {
    /** Merge with existing metadata (true) or replace entirely (false) */
    merge?: boolean;
}

export type {
    Session,
    SessionInsert,
    SessionPaginationOptions,
    SessionStats,
    UpdateMetadataOptions,
};
