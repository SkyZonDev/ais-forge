import fastify, { type FastifyInstance } from 'fastify';
import { routes } from './api';
import { config } from './config';
import { initializeSigningKeys } from './core/keys/services';
import { checkDatabaseHealth } from './utils/db';

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

    return app;
}
