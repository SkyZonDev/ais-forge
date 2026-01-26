import Redis from 'ioredis';

export const redis = new Redis(process.env.REDIS_URL!, {
    // STABILITÉ K8S / CLOUD
    maxRetriesPerRequest: null,
    enableReadyCheck: true,

    // Réseau cloud (latence + failover)
    connectTimeout: 10_000,
    retryStrategy(times) {
        return Math.min(times * 100, 2_000);
    },

    // Sécurité
});
