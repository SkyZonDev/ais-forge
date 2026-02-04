import { and, eq, gt, lt, or, type SQL } from 'drizzle-orm';
import type {
    Cursor,
    CursorPaginationOptions,
    DecodedCursor,
    PaginatedResult,
    PaginationDirection,
    TableWithCursor,
} from '../../types/pagination';

/**
 * Encodes a composite cursor (createdAt + id) into a base64url string.
 * Uses both fields to guarantee uniqueness even when multiple records
 * share the same timestamp.
 *
 * @param createdAt - The creation timestamp of the record
 * @param id - The unique identifier of the record
 * @returns Base64url-encoded cursor string
 */
function encodeCursor(createdAt: Date, id: string): Cursor {
    const payload = JSON.stringify({
        t: createdAt.toISOString(),
        i: id,
    });
    return Buffer.from(payload).toString('base64url');
}

/**
 * Decodes a base64url cursor into its timestamp and ID components.
 *
 * @param cursor - The base64url-encoded cursor string
 * @returns Decoded cursor with createdAt and id
 * @throws {Error} If the cursor format is invalid or cannot be decoded
 */
function decodeCursor(cursor: Cursor): DecodedCursor {
    try {
        const payload = Buffer.from(cursor, 'base64url').toString('utf-8');
        const { t, i } = JSON.parse(payload);
        return {
            createdAt: new Date(t),
            id: i,
        };
    } catch {
        throw new Error('Invalid cursor format');
    }
}

/**
 * Builds a WHERE condition for cursor-based pagination.
 * Uses the composite comparison technique (A, B) > (a, b) to ensure
 * stable pagination even when multiple records share the same timestamp.
 *
 * For DESC ordering (newest first):
 * - 'forward': Returns records BEFORE the cursor (older records)
 * - 'backward': Returns records AFTER the cursor (newer records)
 *
 * @param table - The database table with createdAt and id columns
 * @param cursor - The decoded cursor containing timestamp and ID
 * @param direction - The pagination direction ('forward' or 'backward')
 * @returns SQL condition for filtering records based on cursor position
 */
function buildCursorCondition(
    table: TableWithCursor,
    cursor: DecodedCursor,
    direction: PaginationDirection
): SQL {
    const { createdAt, id } = cursor;

    if (direction === 'forward') {
        // Find records BEFORE the cursor (older records)
        // Condition: (createdAt, id) < (cursor.createdAt, cursor.id)
        return or(
            lt(table.createdAt, createdAt),
            and(eq(table.createdAt, createdAt), lt(table.id, id))
        )!;
    } else {
        // Find records AFTER the cursor (newer records)
        // Condition: (createdAt, id) > (cursor.createdAt, cursor.id)
        return or(
            gt(table.createdAt, createdAt),
            and(eq(table.createdAt, createdAt), gt(table.id, id))
        )!;
    }
}

/**
 * Builds a paginated result with metadata for cursor-based navigation.
 * Determines pagination state (hasNextPage, hasPreviousPage) based on
 * the direction and whether more records are available.
 *
 * @template T - The type of items in the result, must have createdAt and id fields
 * @param results - Array of paginated results
 * @param meta - Pagination metadata
 * @param meta.limit - Maximum number of items requested
 * @param meta.cursor - Optional cursor used for this pagination request
 * @param meta.direction - Direction of pagination ('forward' or 'backward')
 * @param meta.hasMore - Whether more records exist beyond the current page
 * @param meta.totalCount - Optional total count of all records
 * @returns Paginated result with data and pagination metadata
 */
function _buildPaginatedResult<T extends { createdAt: Date; id: string }>(
    results: T[],
    meta: {
        cursor?: Cursor;
        direction: PaginationDirection;
        hasMore: boolean;
        totalCount?: number;
    }
): PaginatedResult<T> {
    const { cursor, direction, hasMore, totalCount } = meta;

    // Determine hasNextPage and hasPreviousPage based on direction
    let hasNextPage: boolean;
    let hasPreviousPage: boolean;

    if (direction === 'forward') {
        // Forward pagination: moving to older records
        hasNextPage = hasMore;
        hasPreviousPage = !!cursor; // Previous page exists if we have a cursor
    } else {
        // Backward pagination: moving to newer records
        hasNextPage = !!cursor; // Next page exists if we navigated backward with a cursor
        hasPreviousPage = hasMore;
    }

    // Generate start and end cursors from the result set
    const firstResult = results[0];
    const lastResult = results[results.length - 1];
    const startCursor = firstResult
        ? encodeCursor(firstResult.createdAt, firstResult.id)
        : null;
    const endCursor = lastResult
        ? encodeCursor(lastResult.createdAt, lastResult.id)
        : null;

    return {
        data: results,
        pagination: {
            hasNextPage,
            hasPreviousPage,
            startCursor,
            endCursor,
            ...(totalCount !== undefined && { totalCount }),
        },
    };
}

export {
    encodeCursor,
    decodeCursor,
    buildCursorCondition,
    _buildPaginatedResult,
};

export type { Cursor, CursorPaginationOptions, PaginatedResult };
