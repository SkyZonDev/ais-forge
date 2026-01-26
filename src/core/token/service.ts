import { refreshTokenRepository } from '../../db/repository/refresh-token.repository';

export async function purgeExpiredToken() {
    const dayAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const [expired, revoked, used] = await Promise.all([
        refreshTokenRepository.deleteExpiredBefore(dayAgo),
        refreshTokenRepository.deleteRevokedBefore(dayAgo),
        refreshTokenRepository.deleteUsedBefore(dayAgo),
    ]);

    return {
        expired,
        revoked,
        used,
    };
}
