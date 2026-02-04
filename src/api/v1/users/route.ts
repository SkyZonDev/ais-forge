import type { FastifyInstance } from 'fastify';
import { authenticate } from '../../../middlewares/auth';
import * as ctrl from './controllers';

export function usersRoutes(app: FastifyInstance) {
    app.get('/me', { preHandler: authenticate() }, ctrl.me);
    app.get('/get-sessions', { preHandler: authenticate() }, ctrl.getSessions);
}
