import cookie from '@fastify/cookie';
import type { FastifyInstance } from 'fastify';

export function plugins(app: FastifyInstance) {
    app.register(cookie);
}
