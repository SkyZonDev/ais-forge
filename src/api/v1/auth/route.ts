import type { FastifyInstance } from 'fastify';
import { authenticate } from '../../../middlewares/auth';
import * as ctrl from './controllers';

export function authRoutes(app: FastifyInstance) {
    app.post('/sign-in', ctrl.signin);
    app.post('/sign-up', ctrl.signup);
    app.post('/logout', ctrl.logout);
    app.post('/refresh-token', ctrl.refresh);

    app.get('/me', { preHandler: authenticate() }, ctrl.me);
}
