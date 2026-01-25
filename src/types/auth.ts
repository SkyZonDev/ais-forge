import { revokedReason } from '../db';

type RevokedReason = (typeof revokedReason)[number];
type RevocationResult<T> = {
    message: string,
    /** Whether the revocation was successful */
    success: boolean;
    /** The revoked result, or null if not found */
    data: T | null;
    /** Reason for revocation failure, if any */
    error?: string;
};

export type { RevokedReason, RevocationResult };
