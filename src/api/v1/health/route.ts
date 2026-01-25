import type { FastifyInstance, FastifyReply } from 'fastify';
import { getKeyHealthStatus } from '../../../core/keys/services';
import { redis } from '../../../utils/db';

export function healthRoute(app: FastifyInstance) {
    app.get('/', (_, res: FastifyReply) => {
        res.status(200).send({
            success: true,
            health: 'ok',
        });
    });

    app.get('/keys', async (req, res) => {
        const status = await getKeyHealthStatus();

        if (!status.hasActiveKey) {
            return res.status(503).send({ status: 'unhealthy', ...status });
        }

        if (status.rotationRecommended) {
            return res.status(200).send({ status: 'warning', ...status });
        }

        res.send({ status: 'healthy', ...status });
    });

    app.get('/redis', async () => {
        await redis.ping();
        return { status: 'ok' };
    });
}
