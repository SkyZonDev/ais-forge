import { and, asc, count, desc, eq, isNull, SQL, sql } from 'drizzle-orm';
import type {
    CreateIdentityParams,
    CreateUserWithOrganizationParams,
    CreateUserWithOrganizationResult,
    FindAllIdentitiesOptions,
    Identity,
    IdentityPublic,
    IdentityStatus,
    IdentityType,
    UpdateIdentityParams,
} from '../../types/identities';
import { db } from '../../utils/db';
import * as schema from '../schema';
import {
    _buildPaginatedResult,
    buildCursorCondition,
    decodeCursor,
    type PaginatedResult,
} from './utils';

// ============================================================================
// EXCEPTIONS
// ============================================================================

/**
 * Base error for the identities repository.
 */
export class IdentityRepositoryError extends Error {
    constructor(
        message: string,
        public readonly code: string,
        public readonly cause?: unknown
    ) {
        super(message);
        this.name = 'IdentityRepositoryError';
    }
}

/**
 * Error thrown when an identity is not found.
 */
export class IdentityNotFoundError extends IdentityRepositoryError {
    constructor(identifier: string) {
        super(`Identity not found: ${identifier}`, 'IDENTITY_NOT_FOUND');
        this.name = 'IdentityNotFoundError';
    }
}

/**
 * Error thrown on conflict (email already used, etc.).
 */
export class IdentityConflictError extends IdentityRepositoryError {
    constructor(message: string, cause?: unknown) {
        super(message, 'IDENTITY_CONFLICT', cause);
        this.name = 'IdentityConflictError';
    }
}

/**
 * Error thrown when a transaction fails.
 */
export class IdentityTransactionError extends IdentityRepositoryError {
    constructor(message: string, cause?: unknown) {
        super(message, 'TRANSACTION_FAILED', cause);
        this.name = 'IdentityTransactionError';
    }
}

// ============================================================================
// REPOSITORY
// ============================================================================

export const identitiesRepository = {
    // ========================================================================
    // READ OPERATIONS
    // ========================================================================

    /**
     * Searches for an active identity by its unique identifier.
     *
     * @param id - The UUID of the identity to search for
     * @returns The found identity or null if not found/inactive
     *
     * @example
     * ```typescript
     * const identity = await identitiesRepository.findById('550e8400-e29b-41d4-a716-446655440000');
     * if (identity) {
     *   console.log(`Found: ${identity.displayName}`);
     * }
     * ```
     */
    async findById(id: string): Promise<IdentityPublic | null> {
        const [identity] = await db
            .select({
                id: schema.identities.id,
                displayName: schema.identities.displayName,
                email: schema.identities.email,
            })
            .from(schema.identities)
            .where(
                and(
                    eq(schema.identities.id, id),
                    eq(schema.identities.status, 'active'),
                    isNull(schema.identities.deletedAt)
                )
            )
            .limit(1);

        return identity ?? null;
    },

    /**
     * Searches for an active identity by its email address.
     *
     * Note: Email is unique per organization, but this method
     * searches globally. For organization-specific search,
     * use `findByEmailInOrganization`.
     *
     * @param email - The email address to search for
     * @returns The found identity or null if not found/inactive
     *
     * @example
     * ```typescript
     * const identity = await identitiesRepository.findByEmail('user@example.com');
     * ```
     */
    async findByEmail(email: string): Promise<IdentityPublic | null> {
        const [identity] = await db
            .select({
                id: schema.identities.id,
                displayName: schema.identities.displayName,
                email: schema.identities.email,
            })
            .from(schema.identities)
            .where(
                and(
                    eq(schema.identities.email, email.toLowerCase()),
                    eq(schema.identities.status, 'active'),
                    isNull(schema.identities.deletedAt)
                )
            )
            .limit(1);

        return identity ?? null;
    },

    /**
     * Searches for an identity by email within a specific organization.
     *
     * @param organizationId - The UUID of the organization
     * @param email - The email address to search for
     * @returns The found identity or null
     *
     * @example
     * ```typescript
     * const identity = await identitiesRepository.findByEmailInOrganization(
     *   'org-uuid',
     *   'user@example.com'
     * );
     * ```
     */
    async findByEmailInOrganization(
        organizationId: string,
        email: string
    ): Promise<IdentityPublic | null> {
        const [identity] = await db
            .select({
                id: schema.identities.id,
                displayName: schema.identities.displayName,
                email: schema.identities.email,
            })
            .from(schema.identities)
            .innerJoin(
                schema.identityOrganizations,
                eq(
                    schema.identityOrganizations.identityId,
                    schema.identities.id
                )
            )
            .where(
                and(
                    eq(
                        schema.identityOrganizations.organizationId,
                        organizationId
                    ),
                    eq(schema.identities.email, email.toLowerCase()),
                    eq(schema.identities.status, 'active'),
                    isNull(schema.identities.deletedAt),
                    isNull(schema.identityOrganizations.leftAt)
                )
            )
            .limit(1);

        return identity ?? null;
    },

    /**
     * Retrieves a complete identity by its ID (including all fields).
     *
     * @param id - The UUID of the identity
     * @returns The complete identity or null
     * @throws {IdentityNotFoundError} If the identity does not exist (optional with throwIfNotFound)
     *
     * @example
     * ```typescript
     * const identity = await identitiesRepository.findFullById('uuid');
     * console.log(identity?.metadata);
     * ```
     */
    async findFullById(id: string): Promise<Identity | null> {
        const [identity] = await db
            .select()
            .from(schema.identities)
            .where(
                and(
                    eq(schema.identities.id, id),
                    isNull(schema.identities.deletedAt)
                )
            )
            .limit(1);

        return identity ?? null;
    },

    /**
     * Lists identities within an organization with filtering and cursor-based pagination.
     *
     * Supports text search on name and email, filtering by type and status,
     * and bidirectional cursor pagination for efficient navigation through large datasets.
     *
     * @param options - Filtering and pagination options
     * @returns Paginated result containing identities and navigation metadata
     *
     * @example
     * ```typescript
     * // Search for active human users
     * const result = await identitiesRepository.findAll({
     *   organizationId: 'org-uuid',
     *   type: 'human',
     *   status: 'active',
     *   search: 'john',
     *   limit: 20
     * });
     *
     * console.log(`Found ${result.data.length} identities`);
     * if (result.pagination.totalCount) {
     *   console.log(`Total: ${result.pagination.totalCount}`);
     * }
     * result.data.forEach(i => console.log(i.displayName));
     *
     * // Navigate to next page
     * if (result.pagination.hasNextPage) {
     *   const nextPage = await identitiesRepository.findAll({
     *     organizationId: 'org-uuid',
     *     cursor: result.pagination.endCursor,
     *     direction: 'forward'
     *   });
     * }
     *
     * // Navigate to previous page
     * if (result.pagination.hasPreviousPage) {
     *   const prevPage = await identitiesRepository.findAll({
     *     organizationId: 'org-uuid',
     *     cursor: result.pagination.startCursor,
     *     direction: 'backward'
     *   });
     * }
     * ```
     */
    async findAll(
        options: FindAllIdentitiesOptions
    ): Promise<PaginatedResult<Identity>> {
        const {
            organizationId,
            type,
            status,
            search,
            limit = 50,
            cursor,
            direction = 'forward',
            includeTotalCount = false,
        } = options;

        // Build WHERE conditions
        const conditions: SQL[] = [
            eq(schema.identityOrganizations.organizationId, organizationId),
            isNull(schema.identities.deletedAt),
            isNull(schema.identityOrganizations.leftAt),
        ];

        if (type) {
            conditions.push(eq(schema.identities.type, type));
        }

        if (status) {
            conditions.push(eq(schema.identities.status, status));
        }

        if (search) {
            const searchPattern = `%${search}%`;
            conditions.push(
                sql`(${schema.identities.displayName} ILIKE ${searchPattern} OR ${schema.identities.email} ILIKE ${searchPattern})`
            );
        }

        // Apply cursor condition for pagination
        if (cursor) {
            const decodedCursor = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(
                    schema.identities,
                    decodedCursor,
                    direction
                )
            );
        }

        // Fetch limit + 1 to determine if more results exist
        const queryLimit = limit + 1;

        let results = await db
            .select({
                id: schema.identities.id,
                type: schema.identities.type,
                status: schema.identities.status,
                displayName: schema.identities.displayName,
                email: schema.identities.email,
                createdAt: schema.identities.createdAt,
                updatedAt: schema.identities.updatedAt,
                lastActivityAt: schema.identities.lastActivityAt,
                deletedAt: schema.identities.deletedAt,
                metadata: schema.identities.metadata,
            })
            .from(schema.identities)
            .innerJoin(
                schema.identityOrganizations,
                eq(
                    schema.identityOrganizations.identityId,
                    schema.identities.id
                )
            )
            .where(and(...conditions))
            .orderBy(
                direction === 'forward'
                    ? desc(schema.identities.createdAt)
                    : asc(schema.identities.createdAt),
                direction === 'forward'
                    ? desc(schema.identities.id)
                    : asc(schema.identities.id)
            )
            .limit(queryLimit);

        // Check if more results exist beyond the current page
        const hasMore = results.length > limit;
        if (hasMore) {
            results = results.slice(0, limit);
        }

        // Reverse results for backward pagination to maintain chronological order
        if (direction === 'backward') {
            results.reverse();
        }

        // Compute total count if requested (note: expensive operation)
        let totalCount: number | undefined;
        if (includeTotalCount) {
            const [countResult] = await db
                .select({ count: count() })
                .from(schema.identities)
                .innerJoin(
                    schema.identityOrganizations,
                    eq(
                        schema.identityOrganizations.identityId,
                        schema.identities.id
                    )
                )
                .where(and(...conditions));
            totalCount = countResult?.count;
        }

        return _buildPaginatedResult(results, {
            ...(cursor && { cursor }),
            direction,
            hasMore,
            ...(totalCount && { totalCount }),
        });
    },

    /**
     * Checks if an identity exists within an organization.
     *
     * @param organizationId - The UUID of the organization
     * @param identityId - The UUID of the identity
     * @returns true if the identity exists and is active
     *
     * @example
     * ```typescript
     * const exists = await identitiesRepository.existsInOrganization(
     *   'org-uuid',
     *   'identity-uuid'
     * );
     * ```
     */
    async existsInOrganization(
        organizationId: string,
        identityId: string
    ): Promise<boolean> {
        const [result] = await db
            .select({ id: schema.identities.id })
            .from(schema.identities)
            .innerJoin(
                schema.identityOrganizations,
                eq(
                    schema.identityOrganizations.identityId,
                    schema.identities.id
                )
            )
            .where(
                and(
                    eq(schema.identities.id, identityId),
                    eq(
                        schema.identityOrganizations.organizationId,
                        organizationId
                    ),
                    eq(schema.identities.status, 'active'),
                    isNull(schema.identities.deletedAt)
                )
            )
            .limit(1);

        return result !== undefined;
    },

    // ========================================================================
    // WRITE OPERATIONS
    // ========================================================================

    /**
     * Creates a new identity within an organization.
     *
     * @param data - The data of the identity to create
     * @returns The created identity
     * @throws {IdentityConflictError} If the email already exists in the organization
     *
     * @example
     * ```typescript
     * const identity = await identitiesRepository.create({
     *   organizationId: 'org-uuid',
     *   displayName: 'Jane Doe',
     *   email: 'jane@example.com',
     *   type: 'human',
     *   metadata: { department: 'Engineering' }
     * });
     * ```
     */
    async create(data: CreateIdentityParams): Promise<Identity> {
        try {
            const [identity] = await db
                .insert(schema.identities)
                .values({
                    displayName: data.displayName,
                    email: data.email?.toLowerCase() ?? null,
                    type: data.type ?? 'human',
                    status: data.status ?? 'active',
                    metadata: data.metadata ?? {},
                    lastActivityAt: new Date(),
                })
                .returning();

            if (!identity) {
                throw new IdentityRepositoryError(
                    'Failed to create identity',
                    'CREATE_FAILED'
                );
            }

            return identity;
        } catch (error) {
            // Check for unique constraint violation
            if (
                error instanceof Error &&
                error.message.includes('identity_org_email_unique_idx')
            ) {
                throw new IdentityConflictError(
                    `Email already exists in organization: ${data.email}`,
                    error
                );
            }
            throw error;
        }
    },

    /**
     * Creates a new user with their organization and credentials.
     *
     * This transactional method atomically creates:
     * 1. The organization
     * 2. The user's identity
     * 3. The authentication method (password)
     *
     * @param data - The data to create the user and organization
     * @returns The created organization, identity, and auth method
     * @throws {IdentityTransactionError} If the transaction fails
     * @throws {IdentityConflictError} If the organization slug already exists
     *
     * @example
     * ```typescript
     * const result = await identitiesRepository.createUserWithOrganization({
     *   displayName: 'John Doe',
     *   email: 'john@example.com',
     *   credentialHash: await hashPassword('secure-password'),
     *   organizationName: 'Acme Corp',
     *   organizationSlug: 'acme-corp'
     * });
     *
     * console.log(`Organization created: ${result.organization.id}`);
     * console.log(`User created: ${result.identity.id}`);
     * ```
     */
    async createUserWithOrganization(
        data: CreateUserWithOrganizationParams
    ): Promise<CreateUserWithOrganizationResult> {
        try {
            const result = await db.transaction(async (tx) => {
                // 1. Create organization
                const [organization] = await tx
                    .insert(schema.organizations)
                    .values({
                        name: data.organizationName,
                        slug: data.organizationSlug.toLowerCase(),
                    })
                    .returning();

                if (!organization) {
                    throw new IdentityTransactionError(
                        'Failed to create organization'
                    );
                }

                // 2. Create identity
                const [identity] = await tx
                    .insert(schema.identities)
                    .values({
                        displayName: data.displayName,
                        email: data.email.toLowerCase(),
                        type: 'human',
                        status: 'active',
                        lastActivityAt: new Date(),
                    })
                    .returning();

                if (!identity) {
                    throw new IdentityTransactionError(
                        'Failed to create identity'
                    );
                }

                // 3. Create identity in org
                const [member] = await tx
                    .insert(schema.identityOrganizations)
                    .values({
                        identityId: identity.id,
                        organizationId: organization.id,
                        isPrimary: true,
                    })
                    .returning();

                if (!member) {
                    throw new IdentityTransactionError(
                        'Failed to create identity member'
                    );
                }

                // 4. Create auth method
                const [authMethod] = await tx
                    .insert(schema.authMethods)
                    .values({
                        identityId: identity.id,
                        organizationId: organization.id,
                        type: 'password',
                        credentialHash: data.credentialHash,
                    })
                    .returning();

                if (!authMethod) {
                    throw new IdentityTransactionError(
                        'Failed to create auth method'
                    );
                }

                return { organization, identity, authMethod };
            });

            return result;
        } catch (error) {
            if (error instanceof IdentityTransactionError) {
                throw error;
            }
            if (
                error instanceof Error &&
                error.message.includes('organizations_slug_unique')
            ) {
                throw new IdentityConflictError(
                    `Organization slug already exists: ${data.organizationSlug}`,
                    error
                );
            }
            throw new IdentityTransactionError(
                'Transaction failed while creating user with organization',
                error
            );
        }
    },

    /**
     * Updates an existing identity.
     *
     * @param id - The UUID of the identity to update
     * @param data - The fields to update
     * @returns The updated identity
     * @throws {IdentityNotFoundError} If the identity does not exist
     * @throws {IdentityConflictError} If the new email is already in use
     *
     * @example
     * ```typescript
     * const updated = await identitiesRepository.update(
     *   'identity-uuid',
     *   {
     *     displayName: 'John Smith',
     *     metadata: { department: 'Sales' }
     *   }
     * );
     * ```
     */
    async update(id: string, data: UpdateIdentityParams): Promise<Identity> {
        try {
            const updateData: Record<string, unknown> = {
                updatedAt: new Date(),
            };

            if (data.displayName !== undefined) {
                updateData.displayName = data.displayName;
            }
            if (data.email !== undefined) {
                updateData.email = data.email?.toLowerCase() ?? null;
            }
            if (data.status !== undefined) {
                updateData.status = data.status;
            }
            if (data.metadata !== undefined) {
                updateData.metadata = data.metadata;
            }

            const [identity] = await db
                .update(schema.identities)
                .set(updateData)
                .where(
                    and(
                        eq(schema.identities.id, id),
                        isNull(schema.identities.deletedAt)
                    )
                )
                .returning();

            if (!identity) {
                throw new IdentityNotFoundError(id);
            }

            return identity;
        } catch (error) {
            if (error instanceof IdentityNotFoundError) {
                throw error;
            }
            if (
                error instanceof Error &&
                error.message.includes('identity_org_email_unique_idx')
            ) {
                throw new IdentityConflictError(
                    `Email already exists in organization: ${data.email}`,
                    error
                );
            }
            throw error;
        }
    },

    /**
     * Updates the last activity date of an identity.
     *
     * This method is optimized to be called frequently
     * (e.g., on every authenticated request).
     *
     * @param id - The UUID of the identity
     *
     * @example
     * ```typescript
     * await identitiesRepository.updateLastActivity('identity-uuid');
     * ```
     */
    async updateLastActivity(id: string): Promise<void> {
        await db
            .update(schema.identities)
            .set({ lastActivityAt: new Date() })
            .where(eq(schema.identities.id, id));
    },

    /**
     * Suspends an identity (makes it inactive without deleting it).
     *
     * @param id - The UUID of the identity to suspend
     * @returns The suspended identity
     * @throws {IdentityNotFoundError} If the identity does not exist
     *
     * @example
     * ```typescript
     * const suspended = await identitiesRepository.suspend('identity-uuid');
     * console.log(suspended.status); // 'suspended'
     * ```
     */
    async suspend(id: string): Promise<Identity> {
        return this.update(id, { status: 'suspended' });
    },

    /**
     * Reactivates a suspended identity.
     *
     * @param id - The UUID of the identity to reactivate
     * @returns The reactivated identity
     * @throws {IdentityNotFoundError} If the identity does not exist
     *
     * @example
     * ```typescript
     * const reactivated = await identitiesRepository.reactivate('identity-uuid');
     * console.log(reactivated.status); // 'active'
     * ```
     */
    async reactivate(id: string): Promise<Identity> {
        return this.update(id, { status: 'active' });
    },

    /**
     * Soft deletes an identity (marks it as deleted).
     *
     * The identity remains in the database but is no longer accessible
     * via standard queries. Data can be purged later by a cleanup job.
     *
     * @param id - The UUID of the identity to delete
     * @returns The deleted identity
     * @throws {IdentityNotFoundError} If the identity does not exist
     *
     * @example
     * ```typescript
     * await identitiesRepository.softDelete('identity-uuid');
     * ```
     */
    async softDelete(id: string): Promise<Identity> {
        const [identity] = await db
            .update(schema.identities)
            .set({
                status: 'deleted',
                deletedAt: new Date(),
                updatedAt: new Date(),
            })
            .where(
                and(
                    eq(schema.identities.id, id),
                    isNull(schema.identities.deletedAt)
                )
            )
            .returning();

        if (!identity) {
            throw new IdentityNotFoundError(id);
        }

        return identity;
    },

    /**
     * Permanently deletes an identity from the database.
     *
     * ⚠️ WARNING: This operation is irreversible and also deletes
     * all related data (sessions, tokens, etc.) via CASCADE constraints.
     *
     * @param id - The UUID of the identity to permanently delete
     * @returns true if deleted, false if not found
     *
     * @example
     * ```typescript
     * const deleted = await identitiesRepository.hardDelete('identity-uuid');
     * if (deleted) {
     *   console.log('Identity permanently deleted');
     * }
     * ```
     */
    async hardDelete(id: string): Promise<boolean> {
        const result = await db
            .delete(schema.identities)
            .where(eq(schema.identities.id, id))
            .returning({ id: schema.identities.id });

        return result.length > 0;
    },

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    /**
     * Counts the number of identities in an organization.
     *
     * @param organizationId - The UUID of the organization
     * @param options - Filtering options (type, status)
     * @returns The number of identities
     *
     * @example
     * ```typescript
     * const totalUsers = await identitiesRepository.countByOrganization(
     *   'org-uuid',
     *   { type: 'human', status: 'active' }
     * );
     * ```
     */
    async countByOrganization(
        organizationId: string,
        options?: { type?: IdentityType; status?: IdentityStatus }
    ): Promise<number> {
        const conditions: SQL[] = [
            eq(schema.identityOrganizations.organizationId, organizationId),
            isNull(schema.identities.deletedAt),
            isNull(schema.identityOrganizations.leftAt),
        ];

        if (options?.type) {
            conditions.push(eq(schema.identities.type, options.type));
        }
        if (options?.status) {
            conditions.push(eq(schema.identities.status, options.status));
        }

        const [result] = await db
            .select({ count: sql<number>`count(*)::int` })
            .from(schema.identities)
            .innerJoin(
                schema.identityOrganizations,
                eq(
                    schema.identityOrganizations.identityId,
                    schema.identities.id
                )
            )
            .where(and(...conditions));

        return result?.count ?? 0;
    },

    /**
     * Retrieves recently active identities within an organization.
     *
     * Useful for dashboards and activity reports.
     *
     * @param organizationId - The UUID of the organization
     * @param since - Date from which to search for activity
     * @param limit - Maximum number of results
     * @returns List of recently active identities
     *
     * @example
     * ```typescript
     * const recentlyActive = await identitiesRepository.findRecentlyActive(
     *   'org-uuid',
     *   new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24h
     *   10
     * );
     * ```
     */
    async findRecentlyActive(
        organizationId: string,
        since: Date,
        limit = 10
    ): Promise<Identity[]> {
        return db
            .select({
                id: schema.identities.id,
                displayName: schema.identities.displayName,
                email: schema.identities.email,
                type: schema.identities.type,
                status: schema.identities.status,
                createdAt: schema.identities.createdAt,
                updatedAt: schema.identities.updatedAt,
                lastActivityAt: schema.identities.lastActivityAt,
                deletedAt: schema.identities.deletedAt,
                metadata: schema.identities.metadata,
            })
            .from(schema.identities)
            .innerJoin(
                schema.identityOrganizations,
                eq(
                    schema.identityOrganizations.identityId,
                    schema.identities.id
                )
            )
            .where(
                and(
                    eq(
                        schema.identityOrganizations.organizationId,
                        organizationId
                    ),
                    eq(schema.identities.status, 'active'),
                    isNull(schema.identities.deletedAt),
                    sql`${schema.identities.lastActivityAt} >= ${since}`
                )
            )
            .orderBy(desc(schema.identities.lastActivityAt))
            .limit(limit);
    },

    /**
     * Merges an identity's metadata with new data.
     *
     * Performs a shallow merge of metadata objects.
     *
     * @param id - The UUID of the identity
     * @param metadata - The metadata to merge
     * @returns The updated identity
     * @throws {IdentityNotFoundError} If the identity does not exist
     *
     * @example
     * ```typescript
     * // Add metadata without overwriting existing ones
     * const updated = await identitiesRepository.mergeMetadata(
     *   'identity-uuid',
     *   { lastLogin: new Date().toISOString(), loginCount: 42 }
     * );
     * ```
     */
    async mergeMetadata(
        id: string,
        metadata: Record<string, unknown>
    ): Promise<Identity> {
        const existing = await this.findFullById(id);
        if (!existing) {
            throw new IdentityNotFoundError(id);
        }

        return this.update(id, {
            metadata: { ...existing.metadata, ...metadata },
        });
    },
};
