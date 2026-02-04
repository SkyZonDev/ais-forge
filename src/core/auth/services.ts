import crypto from 'node:crypto';
import { config } from '../../config';
import { auditRepository } from '../../db/repository/audit.repository';
import { authMethodsRepository } from '../../db/repository/auth/auth-methods.repository';
import { identitiesRepository } from '../../db/repository/identities.repository';
import { organizationsRepository } from '../../db/repository/organizations.repository';
import { refreshTokenRepository } from '../../db/repository/refresh-token.repository';
import { sessionsRepository } from '../../db/repository/session.repository';
import { ApiError } from '../../utils/api/api-error';
import { hashPassword, verifyPassword } from '../../utils/crypto';
import { hashToken } from '../../utils/crypto/password';
import { signToken } from '../keys/services';

interface SigninData {
    email: string;
    password: string;
    rememberMe: boolean;
}

interface SignupData {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
    organizationName: string;
    organizationSlug: string;
    metadata: Record<string, unknown>;
}

interface Finalize {
    id: string;
    email: string | null;
    name: string;
    rememberMe: boolean;
    organizationId: string;
    ipAddress: string;
    userAgent?: string;
    amr?: string[];
}
/**
 * Authenticates a user with email and password.
 *
 * @param data - The signin credentials containing email, password, and rememberMe flag
 * @param ip - The ip of the client
 * @returns Object with success status indicating successful authentication
 * @throws ApiError with code 'EMAIL_OR_PASSWORD_INVALID' if email doesn't exist or password is incorrect
 * @throws ApiError with code 'NO_PASSWORD_CONFIGURED' if no password authentication method is found for the user
 */
export async function signin(data: SigninData, ip: string) {
    // verify existing user
    const identity = await identitiesRepository.findByEmail(data.email);
    if (!identity) {
        throw new ApiError(
            'Email or password invalid',
            400,
            'EMAIL_OR_PASSWORD_INVALID'
        );
    }

    // Vérification password
    const passwordMethod =
        await authMethodsRepository.findActiveByIdentityAndType(
            identity.id,
            'password'
        );
    if (!passwordMethod) {
        throw new ApiError(
            'No password configured',
            400,
            'NO_PASSWORD_CONFIGURED'
        );
    }

    const isValid = await verifyPassword(
        passwordMethod.credentialHash,
        data.password
    );
    if (!isValid) {
        throw new ApiError(
            'Email or password invalid',
            400,
            'EMAIL_OR_PASSWORD_INVALID'
        );
    }

    const org = await organizationsRepository.getPreferredOrganization(
        identity.id
    );
    if (!org) {
        throw new ApiError(
            "User doesn't have organization",
            400,
            'USER_WITHOUT_ORG'
        );
    }

    await auditRepository.create({
        organizationId: passwordMethod.organizationId ?? undefined,
        identityId: identity.id,
        authMethodId: passwordMethod.id,
        eventType: 'auth.login.success',
        eventCategory: 'auth',
        severity: 'info',
        success: true,
    });

    return finalize({
        id: identity.id,
        email: identity.email,
        name: identity.displayName,
        rememberMe: data.rememberMe,
        organizationId: org.id,
        ipAddress: ip,
    });
}

/**
 * Registers a new user and creates their organization.
 *
 * @param data - The signup data containing user information (firstName, lastName, email, password) and organization details (organizationName, organizationSlug)
 * @returns Object with success status indicating successful registration
 * @throws ApiError with code 'EMAIL_ALREADY_EXISTS' if the email is already registered
 */
export async function signup(data: SignupData) {
    // verify existing user
    const user = await identitiesRepository.findByEmail(data.email);
    if (user) {
        throw new ApiError('Email already exists', 401, 'EMAIL_ALREADY_EXISTS');
    }

    const credentialHash = await hashPassword(data.password);

    // Create user
    const { organization, identity, authMethod } =
        await identitiesRepository.createUserWithOrganization({
            organizationName: data.organizationName,
            organizationSlug: data.organizationSlug,
            displayName: `${data.firstName} ${data.lastName}`,
            email: data.email,
            credentialHash,
        });

    // Audit user creation
    await auditRepository.create({
        organizationId: organization.id,
        identityId: identity.id,
        authMethodId: authMethod.id,
        eventType: 'auth.login.success',
        eventCategory: 'auth',
        severity: 'info',
        success: true,
    });

    return {
        id: identity.id,
        email: identity.email,
        displayName: identity.displayName,
    };
}

export async function finalize({
    id,
    email,
    name,
    rememberMe,
    organizationId,
    ipAddress,
    userAgent,
    amr,
}: Finalize) {
    const sessionToken = crypto.randomBytes(32).toString('base64url');
    const refreshToken = crypto.randomBytes(32).toString('base64url');
    const tokenFamilyId = crypto.randomUUID();

    const sessionTokenHash = hashToken(sessionToken);
    const refreshTokenHash = hashToken(refreshToken);

    const refreshTtl = rememberMe
        ? config.security.refreshToken.rememberMeTTLDays * 24 * 60 * 60
        : config.security.refreshToken.ttlDays * 24 * 60 * 60;
    const expiresAt = new Date(Date.now() + refreshTtl);

    const session = await sessionsRepository.create({
        identityId: id,
        organizationId,
        tokenFamilyId,
        sessionTokenHash,
        ipAddress,
        userAgent,
        expiresAt,
    });

    // Create token
    const accessToken = await signToken(
        {
            sub: id,
            sid: session.id,
            scope: '',
            name,
            amr,
            ...(email && { email }),
        },
        {
            issuer: config.security.jwt.issuer,
            algorithm: 'ES256',
            audience: config.security.jwt.audience,
            expiresIn: config.security.jwt.accessTokenTTL,
        }
    );

    await refreshTokenRepository.create({
        identityId: id,
        organizationId,
        sessionId: session.id,
        tokenFamilyId,
        tokenHash: refreshTokenHash,
        expiresAt,
    });

    // Audit log
    await auditRepository.create({
        organizationId,
        identityId: id,
        eventType: 'auth.login.success',
        eventCategory: 'auth',
        severity: 'info',
        success: true,
        metadata: {
            remember_me: rememberMe ?? false,
        },
    });

    return {
        access_token: accessToken,
        refresh_token: refreshToken,
    };
}

export async function logout(sessionId: string) {
    await refreshTokenRepository.revokeBySessionId(sessionId, 'logout');
    const result = await sessionsRepository.revoke(sessionId);
    if (!result.success) {
        throw new ApiError(result.message, 400, result.error);
    }
    return result.data;
}

export async function logoutAll(userId: string) {
    await refreshTokenRepository.revokeAllByIdentityId(userId);
    await sessionsRepository.revokeAllByIdentityId(userId);
}

/**
 * Refreshes an access token using a refresh token.
 *
 * Strategy: No automatic rotation - the refresh token is reused multiple times
 * until it expires or is manually revoked. This is simpler and suitable for
 * most use cases.
 *
 * For rotation strategy (more secure), see refreshTokenWithRotation below.
 */
export async function refreshToken(plainRefreshToken: string) {
    const refreshTokenHash = hashToken(plainRefreshToken);
    console.log(refreshTokenHash);

    const token =
        await refreshTokenRepository.findActiveByTokenHash(refreshTokenHash);
    if (!token) {
        throw new ApiError(
            'Invalid or expired refresh token',
            401,
            'INVALID_REFRESH_TOKEN'
        );
    }

    // Verify session exists and is valid
    if (!token.sessionId) {
        throw new ApiError(
            'Refresh token not associated with session',
            400,
            'INVALID_TOKEN_TYPE'
        );
    }

    const session = await sessionsRepository.findById(token.sessionId);
    if (!session) {
        await refreshTokenRepository.deleteById(token.id);
        throw new ApiError('Session not found', 401, 'SESSION_NOT_FOUND');
    }

    await sessionsRepository.updateLastActivityAt(session.id);

    // Get identity for token claims
    const identity = await identitiesRepository.findById(token.identityId);
    if (!identity) {
        throw new ApiError('Identity not found', 401, 'IDENTITY_NOT_FOUND');
    }

    const accessToken = await signToken(
        {
            sub: token.identityId,
            sid: token.sessionId,
            scope: '',
            name: identity.displayName,
            amr: ['pwd'], // or get from session
            ...(identity.email && { email: identity.email }),
        },
        {
            issuer: config.security.jwt.issuer,
            algorithm: 'ES256',
            audience: config.security.jwt.audience,
            expiresIn: config.security.jwt.accessTokenTTL,
        }
    );

    return {
        accessToken,
        expiresIn: config.security.jwt.accessTokenTTL,
    };
}
