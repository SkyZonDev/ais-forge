import { organizationsRepository } from '../../db/repository/organizations.repository';
import { ApiError } from '../../utils/api/api-error';

interface CreateOrganization {
    name: string;
    slug: string;
    metadata: Record<string, unknown>;
}

export async function create(data: CreateOrganization, userId: string) {
    const org = await organizationsRepository.findBySlug(data.slug);
    if (org) {
        throw new ApiError(
            'Organization slug already exists',
            401,
            'ORGANIZATION_SLUG_ALREADY_EXISTS'
        );
    }

    const organization = await organizationsRepository.create(data, userId);
    if (!organization) {
        throw new ApiError(
            'Error during organization creation',
            401,
            'ERROR_ORGANIZATION_CREATION'
        );
    }

    return organization;
}
