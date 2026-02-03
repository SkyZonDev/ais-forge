import type { FastifyReply, FastifyRequest } from 'fastify';
import * as authServices from '../../../core/auth/services';
import { ApiResponse } from '../../../utils/api/api-response';
import { getIpAddress } from '../../../utils/ip';
import { schema } from './schema';

export async function signin(req: FastifyRequest, res: FastifyReply) {
    try {
        const ip = getIpAddress(req);
        const validatedData = schema.signin.body.parse(req.body);
        const data = await authServices.signin(validatedData, ip);
        return ApiResponse.success(res, data);
    } catch (e) {
        return ApiResponse.handleError(res, e);
    }
}

export async function signup(req: FastifyRequest, res: FastifyReply) {
    try {
        const validatedData = schema.signup.body.parse(req.body);
        const data = await authServices.signup(validatedData);
        return ApiResponse.success(res, data);
    } catch (e) {
        return ApiResponse.handleError(res, e);
    }
}

export async function logout(req: FastifyRequest, res: FastifyReply) {
    try {
        const sessionId = req.headers['session-id'] as string;
        await authServices.logout(sessionId);
        return ApiResponse.success(res, {});
    } catch (e) {
        return ApiResponse.handleError(res, e);
    }
}

export async function refresh(req: FastifyRequest, res: FastifyReply) {
    try {
        const { refreshToken } = schema.refresh.body.parse(req.body);
        const data = await authServices.refreshToken(refreshToken);
        return ApiResponse.success(res, data);
    } catch (e) {
        return ApiResponse.handleError(res, e);
    }
}

export async function me(req: FastifyRequest, res: FastifyReply) {
    try {
        const userId = req.user.sub;
        const data = await authServices.me(userId);
        return ApiResponse.success(res, data);
    } catch (e) {
        return ApiResponse.handleError(res, e);
    }
}
