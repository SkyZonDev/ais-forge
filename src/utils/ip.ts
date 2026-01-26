import type { FastifyRequest } from 'fastify';

export function getIpAddress(req: FastifyRequest): string {
    return (req.headers['x-real-ip'] || // nginx
        req.headers['x-client-ip'] || // apache
        req.headers['x-forwarded-for'] || // use this only if you trust the header
        req.ip) as string;
}
