import type { FastifyReply, FastifyRequest } from 'fastify';
import * as jose from 'jose';
import { config } from '../config';
import { getJWKS } from '../core/keys/services';
import type { JWTClaims } from '../types/crypto';
import { ApiResponse } from '../utils/api/api-response';

declare module 'fastify' {
    interface FastifyRequest {
        claims: JWTClaims;
    }
}

interface AuthenticateOptions {
    roles?: string[];
    permissions?: string[];
}

/**
 * Gets the token from bearer or cookie
 * @param req - The Fastify request object
 * @returns The token from the request
 */
const getTokenFromRequest = (req: FastifyRequest) => {
    let token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        token = req.cookies?.access_token;
    }

    return token;
};

export function authenticate(options?: AuthenticateOptions) {
    return async (req: FastifyRequest, res: FastifyReply) => {
        try {
            const token = getTokenFromRequest(req);
            if (!token) {
                return ApiResponse.unauthorized(res);
            }

            const jwk = await getJWKS();
            const JWKS = jose.createLocalJWKSet(jwk);
            const decoded = await jose.jwtVerify(token, JWKS, {
                issuer: config.security.jwt.issuer,
                audience: config.security.jwt.audience,
            });

            req.claims = decoded.payload as JWTClaims;
        } catch (error) {
            return ApiResponse.handleError(res, error);
        }
    };
}
