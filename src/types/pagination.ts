import type { PgColumn, PgTable } from 'drizzle-orm/pg-core';

/**
 * Base64-encoded composite cursor for pagination.
 * Contains both timestamp and ID to ensure uniqueness even when multiple
 * records share the same timestamp.
 */
type Cursor = string;

/**
 * Decoded cursor components containing timestamp and identifier.
 */
interface DecodedCursor {
    /** Creation timestamp of the record */
    createdAt: Date;
    /** Unique identifier of the record */
    id: string;
}

/**
 * Pagination direction for cursor-based navigation.
 * - 'forward': Navigate to older records (descending order)
 * - 'backward': Navigate to newer records (ascending order)
 */
type PaginationDirection = 'forward' | 'backward';

/**
 * Table type constraint requiring createdAt and id columns for cursor pagination.
 */
type TableWithCursor = PgTable & {
    createdAt: PgColumn;
    id: PgColumn;
};

/** Options de pagination par curseur */
interface CursorPaginationOptions {
    /** Nombre d'éléments à récupérer */
    limit?: number;
    /** Curseur de départ (exclusif) */
    cursor?: Cursor;
    /** Direction de pagination */
    direction?: PaginationDirection;
}

/**
 * Paginated result with metadata for cursor-based navigation.
 *
 * @template T - The type of items in the paginated result
 */
interface PaginatedResult<T> {
    /** Array of paginated items */
    data: T[];
    /** Pagination metadata */
    pagination: {
        /** Whether there are more items after the current page */
        hasNextPage: boolean;
        /** Whether there are more items before the current page */
        hasPreviousPage: boolean;
        /** Cursor pointing to the first item in the result set */
        startCursor: Cursor | null;
        /** Cursor pointing to the last item in the result set */
        endCursor: Cursor | null;
        /** Total count of items (optional, only included if computed) */
        totalCount?: number;
    };
}

export type {
    Cursor,
    DecodedCursor,
    TableWithCursor,
    CursorPaginationOptions,
    PaginatedResult,
    PaginationDirection,
};
