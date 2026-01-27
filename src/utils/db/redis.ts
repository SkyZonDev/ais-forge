import Redis from 'ioredis';
import { config } from '../../config';

export const redis = new Redis(config.redis.url, {
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
