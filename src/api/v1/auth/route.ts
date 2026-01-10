import type { FastifyInstance } from 'fastify';
import * as ctrl from './controllers';

export function authRoutes(app: FastifyInstance) {
    app.post('/signin', ctrl.signin);
    app.post('/signup', ctrl.signup);
}
