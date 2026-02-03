import fastify, { type FastifyInstance } from 'fastify';
import { routes } from './api';
import { config } from './config';
import { initializeSigningKeys } from './core/keys/services';
import { plugins } from './plugins';
import { checkDatabaseHealth } from './utils/db';
import { keyRotationScheduler } from './utils/scheduler/key-rotation';
import { tokenCleanupScheduler } from './utils/scheduler/token-cleanup';

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

    plugins(app);
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

    // 4. Start token cleanup scheduler
    console.log('⏰ Starting token cleanup scheduler...');
    tokenCleanupScheduler.start();
    console.log('✅ Token cleanup scheduler started');

    console.log('✅ Application initialized successfully');

    return app;
}
