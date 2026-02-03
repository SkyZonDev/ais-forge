import type { FastifyInstance } from 'fastify';
import { authRoutes } from './auth/route';
import { healthRoute } from './health/route';
import { usersRoutes } from './users/route';

export function v1Routes(app: FastifyInstance) {
    app.register(healthRoute, { prefix: 'health' });
    app.register(authRoutes, { prefix: 'auth' });
    app.register(usersRoutes, { prefix: 'users' });
}
