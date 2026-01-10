import type { FastifyInstance, FastifyReply } from 'fastify';

export function healthRoute(app: FastifyInstance) {
    app.get('/', (_, res: FastifyReply) => {
        res.status(200).send({
            success: true,
            health: 'ok',
        });
    });
}
