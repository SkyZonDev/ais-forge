import type { FastifyInstance } from 'fastify';
import { getJWKS } from '../core/keys/services';
import { v1Routes } from './v1';

export function routes(app: FastifyInstance) {
    app.get('/.well-known/jwks.json', getJWKS);
    app.register(v1Routes, { prefix: 'v1' });
}
