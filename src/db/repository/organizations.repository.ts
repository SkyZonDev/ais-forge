import { and, asc, count, desc, eq, isNull, SQL, sql } from 'drizzle-orm';
import type {
    CreateOrganizationInput,
    ListOrganizationsOptions,
    Organization,
    UpdateOrganizationInput,
} from '../../types/organizations';
import { ApiError } from '../../utils/api/api-error';
import { db } from '../../utils/db';
import * as schema from '../schema';
import {
    _buildPaginatedResult,
    buildCursorCondition,
    decodeCursor,
    type PaginatedResult,
} from './utils';

// ============================================================================
// Repository
// ============================================================================

export const organizationsRepository = {
    /**
     * Creates a new organization in the database.
     *
     * @param input - The organization data to create
     * @param input.slug - Unique DNS-safe identifier (lowercase alphanumeric with hyphens)
     * @param input.name - Display name of the organization
     * @param input.metadata - Optional extensible metadata object
     * @param identityId - Id of user who create organization
     * @returns The newly created organization record
     * @throws {Error} If slug format is invalid or slug already exists
     *
     * @example
     * ```typescript
     * const org = await organizationsRepository.create({
     *   slug: 'acme-corp',
     *   name: 'Acme Corporation',
     *   metadata: { industry: 'technology' }
     * });
     * ```
     */
    async create(
        input: CreateOrganizationInput,
        identityId: string
    ): Promise<Organization | null> {
        const result = await db.transaction(async (tx) => {
            const [organization] = await tx
                .insert(schema.organizations)
                .values({
                    slug: input.slug,
                    name: input.name,
                    metadata: input.metadata ?? {},
                })
                .returning();

            if (!organization) {
                throw new ApiError(
                    'Error during organization creation',
                    401,
                    'ERROR_ORGANIZATION_CREATION'
                );
            }

            const [member] = await tx
                .insert(schema.identityOrganizations)
                .values({
                    identityId,
                    organizationId: organization.id,
                })
                .returning();
            if (!member) {
                throw new ApiError(
                    'Error during adding identity in org',
                    401,
                    'ERROR_ADD_IDENTITY_ORGANIZATION'
                );
            }

            return organization;
        });

        return result ?? null;
    },

    /**
     * Retrieves an organization by its unique identifier.
     *
     * @param id - The UUID of the organization to find
     * @param options - Optional configuration
     * @param options.includeDeleted - If true, returns soft-deleted organizations (default: false)
     * @returns The organization if found, null otherwise
     *
     * @example
     * ```typescript
     * const org = await organizationsRepository.findById('123e4567-e89b-12d3-a456-426614174000');
     * if (!org) {
     *   throw new NotFoundError('Organization not found');
     * }
     * ```
     */
    async findById(
        id: string,
        options?: { includeDeleted?: boolean }
    ): Promise<Organization | null> {
        const conditions: SQL[] = [eq(schema.organizations.id, id)];

        if (!options?.includeDeleted) {
            conditions.push(isNull(schema.organizations.deletedAt));
        }

        const [organization] = await db
            .select()
            .from(schema.organizations)
            .where(and(...conditions))
            .limit(1);

        return organization ?? null;
    },

    /**
     * Retrieves an organization by its unique slug.
     * Useful for URL-based lookups where the slug is used as an identifier.
     *
     * @param slug - The DNS-safe slug of the organization
     * @param options - Optional configuration
     * @param options.includeDeleted - If true, returns soft-deleted organizations (default: false)
     * @returns The organization if found, null otherwise
     *
     * @example
     * ```typescript
     * // GET /organizations/:slug
     * const org = await organizationsRepository.findBySlug('acme-corp');
     * ```
     */
    async findBySlug(
        slug: string,
        options?: { includeDeleted?: boolean }
    ): Promise<Organization | null> {
        const conditions: SQL[] = [eq(schema.organizations.slug, slug)];

        if (!options?.includeDeleted) {
            conditions.push(isNull(schema.organizations.deletedAt));
        }

        const [organization] = await db
            .select()
            .from(schema.organizations)
            .where(and(...conditions))
            .limit(1);

        return organization ?? null;
    },

    /**
     * Retrieves a paginated list of organizations using cursor-based pagination.
     * Results are ordered by creation date (newest first) with stable pagination
     * guaranteed by composite cursor (createdAt + id).
     *
     * @param options - Pagination and filtering options
     * @param options.limit - Maximum records to return (default: 20, max: 100)
     * @param options.cursor - Cursor pointing to a specific record for pagination
     * @param options.direction - 'forward' for older records, 'backward' for newer (default: 'forward')
     * @param options.includeDeleted - Include soft-deleted organizations (default: false)
     * @returns Paginated result with data and pagination metadata
     *
     * @example
     * ```typescript
     * // First page
     * const firstPage = await organizationsRepository.findAll({ limit: 10 });
     *
     * // Next page using endCursor
     * const nextPage = await organizationsRepository.findAll({
     *   limit: 10,
     *   cursor: firstPage.pagination.endCursor,
     *   direction: 'forward'
     * });
     * ```
     */
    async findAll(
        options?: ListOrganizationsOptions
    ): Promise<PaginatedResult<Organization>> {
        const {
            limit: requestedLimit = 20,
            cursor,
            direction = 'forward',
            includeDeleted = false,
        } = options ?? {};

        // Clamp limit between 1 and 100
        const limit = Math.min(Math.max(requestedLimit, 1), 100);

        // Build WHERE conditions
        const conditions: SQL[] = [];

        if (!includeDeleted) {
            conditions.push(isNull(schema.organizations.deletedAt));
        }

        if (cursor) {
            const decodedCursor = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(
                    schema.organizations,
                    decodedCursor,
                    direction
                )
            );
        }

        // Determine sort order based on direction
        // For DESC (newest first): forward = continue DESC, backward = ASC then reverse
        const orderBy =
            direction === 'forward'
                ? [
                      desc(schema.organizations.createdAt),
                      desc(schema.organizations.id),
                  ]
                : [
                      asc(schema.organizations.createdAt),
                      asc(schema.organizations.id),
                  ];

        // Fetch one extra record to determine if there are more results
        const results = await db
            .select()
            .from(schema.organizations)
            .where(conditions.length > 0 ? and(...conditions) : undefined)
            .orderBy(...orderBy)
            .limit(limit + 1);

        // Check if there are more records
        const hasMore = results.length > limit;
        const paginatedResults = hasMore ? results.slice(0, limit) : results;

        // Reverse results for backward pagination to maintain consistent order
        if (direction === 'backward') {
            paginatedResults.reverse();
        }

        return _buildPaginatedResult(paginatedResults, {
            ...(cursor && { cursor }),
            direction,
            hasMore,
        });
    },

    /**
     * Updates an existing organization with the provided data.
     * Only non-undefined fields in the input will be updated.
     * Automatically updates the `updatedAt` timestamp.
     *
     * @param id - The UUID of the organization to update
     * @param input - Partial organization data to update
     * @param input.slug - New DNS-safe slug (optional)
     * @param input.name - New display name (optional)
     * @param input.metadata - New metadata object (replaces existing, optional)
     * @returns The updated organization, or null if not found
     * @throws {Error} If new slug format is invalid or conflicts with existing
     *
     * @example
     * ```typescript
     * const updated = await organizationsRepository.update(
     *   '123e4567-e89b-12d3-a456-426614174000',
     *   { name: 'Acme Corp International' }
     * );
     * ```
     */
    async update(
        id: string,
        input: UpdateOrganizationInput
    ): Promise<Organization | null> {
        const [organization] = await db
            .update(schema.organizations)
            .set({
                ...input,
                updatedAt: new Date(),
            })
            .where(
                and(
                    eq(schema.organizations.id, id),
                    isNull(schema.organizations.deletedAt)
                )
            )
            .returning();

        return organization ?? null;
    },

    /**
     * Soft-deletes an organization by setting its `deletedAt` timestamp.
     * The organization remains in the database but is excluded from normal queries.
     * Can be restored later using the `restore` method.
     *
     * @param id - The UUID of the organization to soft-delete
     * @returns The soft-deleted organization, or null if not found
     *
     * @example
     * ```typescript
     * const deleted = await organizationsRepository.softDelete(id);
     * if (!deleted) {
     *   throw new NotFoundError('Organization not found');
     * }
     * // Organization can still be restored with restore(id)
     * ```
     */
    async softDelete(id: string): Promise<Organization | null> {
        const [organization] = await db
            .update(schema.organizations)
            .set({
                deletedAt: new Date(),
                updatedAt: new Date(),
            })
            .where(
                and(
                    eq(schema.organizations.id, id),
                    isNull(schema.organizations.deletedAt)
                )
            )
            .returning();

        return organization ?? null;
    },

    /**
     * Restores a previously soft-deleted organization.
     * Clears the `deletedAt` timestamp, making the organization active again.
     *
     * @param id - The UUID of the soft-deleted organization to restore
     * @returns The restored organization, or null if not found or not deleted
     *
     * @example
     * ```typescript
     * const restored = await organizationsRepository.restore(id);
     * if (!restored) {
     *   throw new NotFoundError('Deleted organization not found');
     * }
     * ```
     */
    async restore(id: string): Promise<Organization | null> {
        const [organization] = await db
            .update(schema.organizations)
            .set({
                deletedAt: null,
                updatedAt: new Date(),
            })
            .where(
                and(
                    eq(schema.organizations.id, id),
                    sql`${schema.organizations.deletedAt} IS NOT NULL`
                )
            )
            .returning();

        return organization ?? null;
    },

    /**
     * Permanently deletes an organization from the database.
     * This action is irreversible - use `softDelete` for recoverable deletion.
     *
     * ⚠️ WARNING: This permanently removes the record and all associated data.
     * Consider using `softDelete` instead for most use cases.
     *
     * @param id - The UUID of the organization to permanently delete
     * @returns The deleted organization, or null if not found
     *
     * @example
     * ```typescript
     * // Only use for permanent data removal (e.g., GDPR compliance)
     * const deleted = await organizationsRepository.hardDelete(id);
     * ```
     */
    async hardDelete(id: string): Promise<Organization | null> {
        const [organization] = await db
            .delete(schema.organizations)
            .where(eq(schema.organizations.id, id))
            .returning();

        return organization ?? null;
    },

    /**
     * Counts the total number of organizations matching the given criteria.
     * Useful for displaying total counts in paginated UIs.
     *
     * @param options - Optional filtering options
     * @param options.includeDeleted - Include soft-deleted organizations (default: false)
     * @returns The total count of matching organizations
     *
     * @example
     * ```typescript
     * const totalActive = await organizationsRepository.count();
     * const totalAll = await organizationsRepository.count({ includeDeleted: true });
     * ```
     */
    async count(options?: { includeDeleted?: boolean }): Promise<number> {
        const conditions: SQL[] = [];

        if (!options?.includeDeleted) {
            conditions.push(isNull(schema.organizations.deletedAt));
        }

        const [result] = await db
            .select({ count: count() })
            .from(schema.organizations)
            .where(conditions.length > 0 ? and(...conditions) : undefined);

        return result?.count ?? 0;
    },

    /**
     * Checks if a slug is available for use.
     * Returns true if the slug is not taken by any active organization.
     *
     * @param slug - The slug to check for availability
     * @param excludeId - Optional organization ID to exclude (for updates)
     * @returns True if the slug is available, false otherwise
     *
     * @example
     * ```typescript
     * // Check before creating
     * const isAvailable = await organizationsRepository.isSlugAvailable('new-slug');
     *
     * // Check during update (exclude current org)
     * const isAvailable = await organizationsRepository.isSlugAvailable('new-slug', currentOrgId);
     * ```
     */
    async isSlugAvailable(slug: string, excludeId?: string): Promise<boolean> {
        const conditions: SQL[] = [
            eq(schema.organizations.slug, slug),
            isNull(schema.organizations.deletedAt),
        ];

        if (excludeId) {
            conditions.push(sql`${schema.organizations.id} != ${excludeId}`);
        }

        const [result] = await db
            .select({ count: count() })
            .from(schema.organizations)
            .where(and(...conditions));

        return (result?.count ?? 0) === 0;
    },

    /**
     * Retrieves the most appropriate organization for an identity.
     *
     * Priority order:
     * 1. The primary organization (if set and active)
     * 2. The most recently joined organization (if multiple exist)
     * 3. The only organization (if there's just one)
     * 4. The first organization found (fallback)
     *
     * @param identityId - The UUID of the identity
     * @returns The organization or null if the identity has no organizations
     *
     * @example
     * ```typescript
     * const org = await identitiesRepository.getPreferredOrganization('identity-uuid');
     * if (org) {
     *   console.log(`Using organization: ${org.name}`);
     * }
     * ```
     */
    async getPreferredOrganization(
        identityId: string
    ): Promise<Organization | null> {
        // First, try to get the primary organization
        const [primaryOrg] = await db
            .select({
                id: schema.organizations.id,
                slug: schema.organizations.slug,
                name: schema.organizations.name,
                createdAt: schema.organizations.createdAt,
                updatedAt: schema.organizations.updatedAt,
                deletedAt: schema.organizations.deletedAt,
                metadata: schema.organizations.metadata,
            })
            .from(schema.identityOrganizations)
            .innerJoin(
                schema.organizations,
                eq(
                    schema.identityOrganizations.organizationId,
                    schema.organizations.id
                )
            )
            .where(
                and(
                    eq(schema.identityOrganizations.identityId, identityId),
                    eq(schema.identityOrganizations.isPrimary, true),
                    isNull(schema.identityOrganizations.leftAt),
                    isNull(schema.organizations.deletedAt)
                )
            )
            .limit(1);

        if (primaryOrg) {
            return primaryOrg;
        }

        // If no primary org, get all active organizations
        const [orgs] = await db
            .select({
                id: schema.organizations.id,
                slug: schema.organizations.slug,
                name: schema.organizations.name,
                createdAt: schema.organizations.createdAt,
                updatedAt: schema.organizations.updatedAt,
                deletedAt: schema.organizations.deletedAt,
                metadata: schema.organizations.metadata,
                joinedAt: schema.identityOrganizations.joinedAt,
            })
            .from(schema.identityOrganizations)
            .innerJoin(
                schema.organizations,
                eq(
                    schema.identityOrganizations.organizationId,
                    schema.organizations.id
                )
            )
            .where(
                and(
                    eq(schema.identityOrganizations.identityId, identityId),
                    isNull(schema.identityOrganizations.leftAt),
                    isNull(schema.organizations.deletedAt)
                )
            )
            .orderBy(desc(schema.identityOrganizations.joinedAt));

        if (!orgs) return null;

        // Return the most recently joined organization (first in the sorted list)
        const { joinedAt, ...org } = orgs;
        return org;
    },
};
