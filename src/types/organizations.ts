import * as schema from '../db/schema';
import type { Cursor } from './pagination';

/** Represents a complete organization record from the database */
type Organization = typeof schema.organizations.$inferSelect;

/** Represents the data required to create a new organization */
type CreateOrganizationInput = {
    slug: string;
    name: string;
    metadata?: Record<string, unknown>;
};

/** Represents the data that can be updated on an organization */
type UpdateOrganizationInput = Partial<{
    slug: string;
    name: string;
    metadata: Record<string, unknown>;
}>;

/** Options for listing organizations with cursor-based pagination */
type ListOrganizationsOptions = {
    /** Maximum number of records to return (default: 20, max: 100) */
    limit?: number;
    /** Cursor for pagination - points to a specific record */
    cursor?: Cursor;
    /** Direction of pagination relative to the cursor */
    direction?: 'forward' | 'backward';
    /** Whether to include soft-deleted organizations */
    includeDeleted?: boolean;
};

export type {
    Organization,
    CreateOrganizationInput,
    UpdateOrganizationInput,
    ListOrganizationsOptions,
};
