import type { FastifyReply, FastifyRequest } from 'fastify';
import * as userServices from '../../../core/users/services';
import { ApiResponse } from '../../../utils/api/api-response';

export async function me(req: FastifyRequest, res: FastifyReply) {
    try {
        const userId = req.claims.sub;
        const data = await userServices.me(userId);
        return ApiResponse.success(res, data);
    } catch (e) {
        return ApiResponse.handleError(res, e);
    }
}

export async function getSessions(req: FastifyRequest, res: FastifyReply) {
    try {
        const userId = req.claims.sub;
        const data = await userServices.getSessions(userId);
        return ApiResponse.success(res, data);
    } catch (e) {
        return ApiResponse.handleError(res, e);
    }
}
