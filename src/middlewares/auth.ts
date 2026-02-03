import type { FastifyReply, FastifyRequest } from 'fastify';
import * as jose from 'jose';
import { config } from '../config';
import { getJWKS } from '../core/keys/services';
import type { JWTClaims } from '../types/crypto';

declare module 'fastify' {
    interface FastifyRequest {
        user: JWTClaims;
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
        const token = getTokenFromRequest(req);
        if (!token) {
            return res.status(401).send({ error: 'Unauthorized' });
        }

        const jwk = await getJWKS();
        const JWKS = jose.createLocalJWKSet(jwk);
        const decoded = await jose.jwtVerify(token, JWKS, {
            issuer: config.security.jwt.issuer,
            audience: config.security.jwt.audience,
        });

        req.user = decoded.payload as JWTClaims;
    };
}
