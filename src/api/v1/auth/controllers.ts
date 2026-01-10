import type { FastifyReply, FastifyRequest } from 'fastify';
import * as authServices from '../../../core/auth/services';
import { ApiResponse } from '../../../utils/api/api-response';
import { schema } from './schema';

export async function signin(req: FastifyRequest, res: FastifyReply) {
    try {
        const validatedData = schema.signin.body.parse(req.body);
        const data = await authServices.signin(validatedData);
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
