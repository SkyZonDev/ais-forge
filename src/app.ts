import fastify, { type FastifyInstance } from 'fastify';
import { routes } from './api';
import { config } from './config';
import { initializeSigningKeys } from './core/keys/services';
import { checkDatabaseHealth } from './utils/db';
import { keyRotationScheduler } from './utils/scheduler/key-rotation';

export async function buildApp(): Promise<FastifyInstance> {
    const app = fastify({
        logger: true,
        ignoreTrailingSlash: true,
        caseSensitive: false,
        requestTimeout: 30000,
        connectionTimeout: 10000,
        keepAliveTimeout: 72000,
        bodyLimit: 10 * 1024 * 1024,
        maxParamLength: 500,
        trustProxy: config.isProduction,
        disableRequestLogging: config.isProduction,
    });

    app.register(routes);

    const healthDb = await checkDatabaseHealth();
    if (!healthDb) {
        app.log.error('Database not healthy');
        process.exit(1);
    }

    const initialKey = await initializeSigningKeys();
    if (initialKey) {
        console.log(`Created initial signing key: ${initialKey.kid}`);
    }

    // 3. Start key rotation scheduler
    console.log('⏰ Starting key rotation scheduler...');
    keyRotationScheduler.start();
    console.log('✅ Key rotation scheduler started');

    // 4. Schedule refresh token cleanup (daily at 3 AM)
    // console.log('🧹 Scheduling token cleanup...');
    // cron.schedule('0 3 * * *', async () => {
    //     try {
    //         const purgedCount = await purgeExpiredKeys();
    //         console.log(`🧹 Purged ${purgedCount} expired refresh tokens`);
    //     } catch (error) {
    //         console.error('❌ Token cleanup failed:', error);
    //     }
    // });
    // console.log('✅ Token cleanup scheduled');

    console.log('✅ Application initialized successfully');

    return app;
}
