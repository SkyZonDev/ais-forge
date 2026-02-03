import { identitiesRepository } from '../../db/repository/identities.repository';
import { sessionsRepository } from '../../db/repository/session.repository';
import { ApiError } from '../../utils/api/api-error';

/**
 * Gets the current user's session information.
 *
 * @param userId - The user ID
 * @returns Object with session information
 * @throws ApiError with code 'SESSION_NOT_FOUND' if the session is not found
 */
export async function me(userId: string) {
    const user = await identitiesRepository.findById(userId);
    if (!user) {
        throw new ApiError('User not found', 401, 'USER_NOT_FOUND');
    }
    return user;
}

export async function getSessions(userId: string) {
    const sessions = await sessionsRepository.findActiveByIdentityId(userId);
    if (!sessions) {
        throw new ApiError('Session not found', 401, 'SESSION_NOT_FOUND');
    }
    return sessions.map((session) => ({
        id: session.id,
        ipAddress: session.ipAddress,
        userAgent: session.userAgent,
        lastActivityAt: session.lastActivityAt,
        expiresAt: session.expiresAt,
    }));
}
