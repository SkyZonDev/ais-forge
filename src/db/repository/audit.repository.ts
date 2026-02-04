import {
    and,
    asc,
    count,
    desc,
    eq,
    gte,
    lte,
    or,
    type SQL,
    sql,
} from 'drizzle-orm';
import type {
    AuditLogFilterOptions,
    CreateAuditLogData,
    EventCategory,
    EventSeverity,
} from '../../types/audit';
import { db } from '../../utils/db';
import * as schema from '../schema';
import {
    _buildPaginatedResult,
    buildCursorCondition,
    type CursorPaginationOptions,
    decodeCursor,
    type PaginatedResult,
} from './utils';

// ============================================================================
// Repository
// ============================================================================

export const auditRepository = {
    // ========================================================================
    // Single Record Operations
    // ========================================================================

    async findById(id: string) {
        const [result] = await db
            .select()
            .from(schema.auditLogs)
            .where(eq(schema.auditLogs.id, id))
            .limit(1);
        return result ?? null;
    },

    async create(data: CreateAuditLogData) {
        const [result] = await db
            .insert(schema.auditLogs)
            .values(data)
            .returning();
        return result;
    },

    // ========================================================================
    // Paginated Queries with Cursor
    // ========================================================================

    /**
     * Recherche les logs d'une organisation avec pagination par curseur
     */
    async findByOrganization(
        organizationId: string,
        options: CursorPaginationOptions &
            AuditLogFilterOptions & { includeTotalCount?: boolean } = {}
    ): Promise<PaginatedResult<typeof schema.auditLogs.$inferSelect>> {
        const {
            limit = 50,
            cursor,
            direction = 'forward',
            includeTotalCount = false,
            ...filters
        } = options;

        // Build conditions
        const conditions: SQL[] = [
            eq(schema.auditLogs.organizationId, organizationId),
        ];

        // Ajouter les filtres
        this._addFilterConditions(conditions, filters);

        // Ajouter la condition de curseur si présent
        if (cursor) {
            const decodedCursor = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.auditLogs, decodedCursor, direction)
            );
        }

        // Récupérer limit + 1 pour savoir s'il y a une page suivante
        const queryLimit = limit + 1;

        // Exécuter la requête
        let results = await db
            .select()
            .from(schema.auditLogs)
            .where(and(...conditions))
            .orderBy(
                direction === 'forward'
                    ? desc(schema.auditLogs.createdAt)
                    : asc(schema.auditLogs.createdAt),
                direction === 'forward'
                    ? desc(schema.auditLogs.id)
                    : asc(schema.auditLogs.id)
            )
            .limit(queryLimit);

        // Déterminer s'il y a plus de résultats
        const hasMore = results.length > limit;
        if (hasMore) {
            results = results.slice(0, limit);
        }

        // Si backward, inverser pour avoir l'ordre chronologique décroissant
        if (direction === 'backward') {
            results.reverse();
        }

        // Calculer le total si demandé
        let totalCount: number | undefined;
        if (includeTotalCount) {
            const [countResult] = await db
                .select({ count: count() })
                .from(schema.auditLogs)
                .where(and(...conditions));
            totalCount = countResult?.count;
        }

        // Construire la réponse paginée
        return _buildPaginatedResult(results, {
            ...(cursor && { cursor }),
            direction,
            hasMore,
            ...(totalCount && { totalCount }),
        });
    },

    /**
     * Recherche les logs d'une identité avec pagination par curseur
     */
    async findByIdentity(
        identityId: string,
        options: CursorPaginationOptions &
            Pick<AuditLogFilterOptions, 'startDate' | 'endDate'> = {}
    ): Promise<PaginatedResult<typeof schema.auditLogs.$inferSelect>> {
        const {
            limit = 50,
            cursor,
            direction = 'forward',
            startDate,
            endDate,
        } = options;

        const conditions: SQL[] = [eq(schema.auditLogs.identityId, identityId)];

        if (startDate)
            conditions.push(gte(schema.auditLogs.createdAt, startDate));
        if (endDate) conditions.push(lte(schema.auditLogs.createdAt, endDate));

        if (cursor) {
            const decodedCursor = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.auditLogs, decodedCursor, direction)
            );
        }

        const queryLimit = limit + 1;

        let results = await db
            .select()
            .from(schema.auditLogs)
            .where(and(...conditions))
            .orderBy(
                direction === 'forward'
                    ? desc(schema.auditLogs.createdAt)
                    : asc(schema.auditLogs.createdAt),
                direction === 'forward'
                    ? desc(schema.auditLogs.id)
                    : asc(schema.auditLogs.id)
            )
            .limit(queryLimit);

        const hasMore = results.length > limit;
        if (hasMore) results = results.slice(0, limit);
        if (direction === 'backward') results.reverse();

        return _buildPaginatedResult(results, {
            ...(cursor && { cursor }),
            direction,
            hasMore,
        });
    },

    /**
     * Recherche les logs par adresse IP avec pagination par curseur
     */
    async findByIpAddress(
        ipAddress: string,
        options: CursorPaginationOptions &
            Pick<AuditLogFilterOptions, 'startDate' | 'endDate'> = {}
    ): Promise<PaginatedResult<typeof schema.auditLogs.$inferSelect>> {
        const {
            limit = 50,
            cursor,
            direction = 'forward',
            startDate,
            endDate,
        } = options;

        const conditions: SQL[] = [eq(schema.auditLogs.ipAddress, ipAddress)];

        if (startDate)
            conditions.push(gte(schema.auditLogs.createdAt, startDate));
        if (endDate) conditions.push(lte(schema.auditLogs.createdAt, endDate));

        if (cursor) {
            const decodedCursor = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.auditLogs, decodedCursor, direction)
            );
        }

        const queryLimit = limit + 1;

        let results = await db
            .select()
            .from(schema.auditLogs)
            .where(and(...conditions))
            .orderBy(
                direction === 'forward'
                    ? desc(schema.auditLogs.createdAt)
                    : asc(schema.auditLogs.createdAt),
                direction === 'forward'
                    ? desc(schema.auditLogs.id)
                    : asc(schema.auditLogs.id)
            )
            .limit(queryLimit);

        const hasMore = results.length > limit;
        if (hasMore) results = results.slice(0, limit);
        if (direction === 'backward') results.reverse();

        return _buildPaginatedResult(results, {
            ...(cursor && { cursor }),
            direction,
            hasMore,
        });
    },

    /**
     * Recherche les incidents de sécurité avec pagination par curseur
     */
    async findSecurityIncidents(
        organizationId: string,
        options: CursorPaginationOptions &
            Pick<AuditLogFilterOptions, 'startDate' | 'endDate'> = {}
    ): Promise<PaginatedResult<typeof schema.auditLogs.$inferSelect>> {
        const {
            limit = 50,
            cursor,
            direction = 'forward',
            startDate,
            endDate,
        } = options;

        const conditions: SQL[] = [
            eq(schema.auditLogs.organizationId, organizationId),
            or(
                eq(schema.auditLogs.eventCategory, 'security'),
                eq(schema.auditLogs.severity, 'critical')
            )!,
        ];

        if (startDate)
            conditions.push(gte(schema.auditLogs.createdAt, startDate));
        if (endDate) conditions.push(lte(schema.auditLogs.createdAt, endDate));

        if (cursor) {
            const decodedCursor = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.auditLogs, decodedCursor, direction)
            );
        }

        const queryLimit = limit + 1;

        let results = await db
            .select()
            .from(schema.auditLogs)
            .where(and(...conditions))
            .orderBy(
                direction === 'forward'
                    ? desc(schema.auditLogs.createdAt)
                    : asc(schema.auditLogs.createdAt),
                direction === 'forward'
                    ? desc(schema.auditLogs.id)
                    : asc(schema.auditLogs.id)
            )
            .limit(queryLimit);

        const hasMore = results.length > limit;
        if (hasMore) results = results.slice(0, limit);
        if (direction === 'backward') results.reverse();

        return _buildPaginatedResult(results, {
            ...(cursor && { cursor }),
            direction,
            hasMore,
        });
    },

    /**
     * Recherche les tentatives échouées avec pagination par curseur
     */
    async findFailedAttempts(
        organizationId: string,
        options: CursorPaginationOptions &
            Pick<
                AuditLogFilterOptions,
                'startDate' | 'endDate' | 'ipAddress' | 'identityId'
            > = {}
    ): Promise<PaginatedResult<typeof schema.auditLogs.$inferSelect>> {
        const {
            limit = 50,
            cursor,
            direction = 'forward',
            startDate,
            endDate,
            ipAddress,
            identityId,
        } = options;

        const conditions: SQL[] = [
            eq(schema.auditLogs.organizationId, organizationId),
            eq(schema.auditLogs.success, false),
        ];

        if (startDate)
            conditions.push(gte(schema.auditLogs.createdAt, startDate));
        if (endDate) conditions.push(lte(schema.auditLogs.createdAt, endDate));
        if (ipAddress)
            conditions.push(eq(schema.auditLogs.ipAddress, ipAddress));
        if (identityId)
            conditions.push(eq(schema.auditLogs.identityId, identityId));

        if (cursor) {
            const decodedCursor = decodeCursor(cursor);
            conditions.push(
                buildCursorCondition(schema.auditLogs, decodedCursor, direction)
            );
        }

        const queryLimit = limit + 1;

        let results = await db
            .select()
            .from(schema.auditLogs)
            .where(and(...conditions))
            .orderBy(
                direction === 'forward'
                    ? desc(schema.auditLogs.createdAt)
                    : asc(schema.auditLogs.createdAt),
                direction === 'forward'
                    ? desc(schema.auditLogs.id)
                    : asc(schema.auditLogs.id)
            )
            .limit(queryLimit);

        const hasMore = results.length > limit;
        if (hasMore) results = results.slice(0, limit);
        if (direction === 'backward') results.reverse();

        return _buildPaginatedResult(results, {
            ...(cursor && { cursor }),
            direction,
            hasMore,
        });
    },

    // ========================================================================
    // Aggregation & Statistics
    // ========================================================================

    /**
     * Compte les logs avec filtres optionnels
     */
    async countByOrganization(
        organizationId: string,
        options: AuditLogFilterOptions = {}
    ): Promise<number> {
        const conditions: SQL[] = [
            eq(schema.auditLogs.organizationId, organizationId),
        ];
        this._addFilterConditions(conditions, options);

        const [result] = await db
            .select({ count: count() })
            .from(schema.auditLogs)
            .where(and(...conditions));

        return result?.count ?? 0;
    },

    /**
     * Statistiques par type d'événement
     */
    async getEventTypeStats(
        organizationId: string,
        options: Pick<AuditLogFilterOptions, 'startDate' | 'endDate'> = {}
    ) {
        const conditions: SQL[] = [
            eq(schema.auditLogs.organizationId, organizationId),
        ];

        if (options.startDate)
            conditions.push(gte(schema.auditLogs.createdAt, options.startDate));
        if (options.endDate)
            conditions.push(lte(schema.auditLogs.createdAt, options.endDate));

        return db
            .select({
                eventType: schema.auditLogs.eventType,
                count: count(),
                successCount: sql<number>`count(*) filter (where ${schema.auditLogs.success} = true)::int`,
                failureCount: sql<number>`count(*) filter (where ${schema.auditLogs.success} = false)::int`,
            })
            .from(schema.auditLogs)
            .where(and(...conditions))
            .groupBy(schema.auditLogs.eventType)
            .orderBy(desc(sql`count(*)`));
    },

    /**
     * Statistiques par catégorie d'événement
     */
    async getEventCategoryStats(
        organizationId: string,
        options: Pick<AuditLogFilterOptions, 'startDate' | 'endDate'> = {}
    ) {
        const conditions: SQL[] = [
            eq(schema.auditLogs.organizationId, organizationId),
        ];

        if (options.startDate)
            conditions.push(gte(schema.auditLogs.createdAt, options.startDate));
        if (options.endDate)
            conditions.push(lte(schema.auditLogs.createdAt, options.endDate));

        return db
            .select({
                eventCategory: schema.auditLogs.eventCategory,
                count: count(),
                successCount: sql<number>`count(*) filter (where ${schema.auditLogs.success} = true)::int`,
                failureCount: sql<number>`count(*) filter (where ${schema.auditLogs.success} = false)::int`,
            })
            .from(schema.auditLogs)
            .where(and(...conditions))
            .groupBy(schema.auditLogs.eventCategory)
            .orderBy(desc(sql`count(*)`));
    },

    /**
     * Statistiques par sévérité
     */
    async getSeverityStats(
        organizationId: string,
        options: Pick<AuditLogFilterOptions, 'startDate' | 'endDate'> = {}
    ) {
        const conditions: SQL[] = [
            eq(schema.auditLogs.organizationId, organizationId),
        ];

        if (options.startDate)
            conditions.push(gte(schema.auditLogs.createdAt, options.startDate));
        if (options.endDate)
            conditions.push(lte(schema.auditLogs.createdAt, options.endDate));

        return db
            .select({
                severity: schema.auditLogs.severity,
                count: count(),
            })
            .from(schema.auditLogs)
            .where(and(...conditions))
            .groupBy(schema.auditLogs.severity)
            .orderBy(desc(sql`count(*)`));
    },

    /**
     * Timeline des événements groupés par intervalle
     */
    async getTimeline(
        organizationId: string,
        options: {
            startDate: Date;
            endDate: Date;
            interval?: 'hour' | 'day' | 'week' | 'month';
        }
    ) {
        const { startDate, endDate, interval = 'day' } = options;

        const dateTrunc = sql`date_trunc(${interval}, ${schema.auditLogs.createdAt})`;

        return db
            .select({
                period: sql<string>`${dateTrunc}::text`.as('period'),
                count: count(),
                successCount: sql<number>`count(*) filter (where ${schema.auditLogs.success} = true)::int`,
                failureCount: sql<number>`count(*) filter (where ${schema.auditLogs.success} = false)::int`,
            })
            .from(schema.auditLogs)
            .where(
                and(
                    eq(schema.auditLogs.organizationId, organizationId),
                    gte(schema.auditLogs.createdAt, startDate),
                    lte(schema.auditLogs.createdAt, endDate)
                )
            )
            .groupBy(dateTrunc)
            .orderBy(asc(dateTrunc));
    },

    /**
     * Top des adresses IP par nombre d'événements
     */
    async getTopIpAddresses(
        organizationId: string,
        options: Pick<AuditLogFilterOptions, 'startDate' | 'endDate'> & {
            limit?: number;
        } = {}
    ) {
        const { startDate, endDate, limit = 10 } = options;
        const conditions: SQL[] = [
            eq(schema.auditLogs.organizationId, organizationId),
            sql`${schema.auditLogs.ipAddress} IS NOT NULL`,
        ];

        if (startDate)
            conditions.push(gte(schema.auditLogs.createdAt, startDate));
        if (endDate) conditions.push(lte(schema.auditLogs.createdAt, endDate));

        return db
            .select({
                ipAddress: schema.auditLogs.ipAddress,
                count: count(),
                failureCount: sql<number>`count(*) filter (where ${schema.auditLogs.success} = false)::int`,
                lastSeen: sql<Date>`max(${schema.auditLogs.createdAt})`,
            })
            .from(schema.auditLogs)
            .where(and(...conditions))
            .groupBy(schema.auditLogs.ipAddress)
            .orderBy(desc(sql`count(*)`))
            .limit(limit);
    },

    // ========================================================================
    // Maintenance
    // ========================================================================

    /**
     * Supprime les logs antérieurs à une date
     */
    async deleteOldLogs(organizationId: string, beforeDate: Date) {
        return db
            .delete(schema.auditLogs)
            .where(
                and(
                    eq(schema.auditLogs.organizationId, organizationId),
                    lte(schema.auditLogs.createdAt, beforeDate)
                )
            )
            .returning({ id: schema.auditLogs.id });
    },

    /**
     * Archive les logs dans une table d'archive (retourne les IDs pour traitement batch)
     */
    async getLogsToArchive(
        organizationId: string,
        beforeDate: Date,
        options: { limit?: number } = {}
    ) {
        const { limit = 1000 } = options;

        return db
            .select()
            .from(schema.auditLogs)
            .where(
                and(
                    eq(schema.auditLogs.organizationId, organizationId),
                    lte(schema.auditLogs.createdAt, beforeDate)
                )
            )
            .orderBy(asc(schema.auditLogs.createdAt))
            .limit(limit);
    },

    // ========================================================================
    // Private Helpers
    // ========================================================================

    /**
     * Ajoute les conditions de filtre à un tableau de conditions
     */
    _addFilterConditions(
        conditions: SQL[],
        filters: AuditLogFilterOptions
    ): void {
        if (filters.startDate) {
            conditions.push(gte(schema.auditLogs.createdAt, filters.startDate));
        }
        if (filters.endDate) {
            conditions.push(lte(schema.auditLogs.createdAt, filters.endDate));
        }
        if (filters.eventCategory) {
            conditions.push(
                eq(schema.auditLogs.eventCategory, filters.eventCategory)
            );
        }
        if (filters.severity) {
            conditions.push(eq(schema.auditLogs.severity, filters.severity));
        }
        if (filters.eventType) {
            conditions.push(eq(schema.auditLogs.eventType, filters.eventType));
        }
        if (filters.success !== undefined) {
            conditions.push(eq(schema.auditLogs.success, filters.success));
        }
        if (filters.ipAddress) {
            conditions.push(eq(schema.auditLogs.ipAddress, filters.ipAddress));
        }
        if (filters.identityId) {
            conditions.push(
                eq(schema.auditLogs.identityId, filters.identityId)
            );
        }
        if (filters.resourceType) {
            conditions.push(
                eq(schema.auditLogs.resourceType, filters.resourceType)
            );
        }
        if (filters.resourceId) {
            conditions.push(
                eq(schema.auditLogs.resourceId, filters.resourceId)
            );
        }
    },
};

// ============================================================================
// Export utilities for external use
// ============================================================================

export type {
    AuditLogFilterOptions,
    CreateAuditLogData,
    EventCategory,
    EventSeverity,
};
