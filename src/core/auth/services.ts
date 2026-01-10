import { auditRepository } from '../../db/repository/audit.repository';
import { authMethodsRepository } from '../../db/repository/auth/auth-methods.repository';
import { identitiesRepository } from '../../db/repository/identities.repository';
import { ApiError } from '../../utils/api/api-error';
import { hashPassword, verifyPassword } from '../../utils/crypto';

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
}

/**
 * Authenticates a user with email and password.
 *
 * @param data - The signin credentials containing email, password, and rememberMe flag
 * @returns Object with success status indicating successful authentication
 * @throws ApiError with code 'EMAIL_OR_PASSWORD_INVALID' if email doesn't exist or password is incorrect
 * @throws ApiError with code 'NO_PASSWORD_CONFIGURED' if no password authentication method is found for the user
 */
export async function signin(data: SigninData) {
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

    await auditRepository.create({
        organizationId: passwordMethod.organizationId,
        identityId: identity.id,
        authMethodId: passwordMethod.id,
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
