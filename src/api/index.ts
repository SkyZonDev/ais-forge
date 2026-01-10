import type { FastifyInstance } from 'fastify';
import { v1Routes } from './v1';

export function routes(app: FastifyInstance) {
    app.register(v1Routes, { prefix: 'v1' });
}
