import type { FastifyInstance, FastifyReply } from 'fastify';
import { getJWKS } from '../core/keys/services';
import { v1Routes } from './v1';

export function routes(app: FastifyInstance) {
    app.get('/.well-known/jwks.json', async (_, reply: FastifyReply) => {
        const jwks = await getJWKS();
        // Cache for 1 hour to reduce load
        reply.header('Cache-Control', 'public, max-age=3600');

        return jwks;
    });
    app.register(v1Routes, { prefix: 'v1' });
}
