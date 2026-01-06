import fastify, { type FastifyInstance } from 'fastify';
import { config } from './config';

export async function buildApp(): Promise<FastifyInstance> {
    const app = fastify({
        logger: false,
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

    return app;
}
