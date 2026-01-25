import type { FastifyInstance } from 'fastify';
import * as ctrl from './controllers';

export function authRoutes(app: FastifyInstance) {
    app.post('/sign-in', ctrl.signin);
    app.post('/sign-up', ctrl.signup);
    app.post('/logout', ctrl.logout);
}
