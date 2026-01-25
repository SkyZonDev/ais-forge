import { sql } from 'drizzle-orm';
import {
    boolean,
    check,
    index,
    inet,
    jsonb,
    pgTable,
    text,
    timestamp,
    uuid,
    varchar,
} from 'drizzle-orm/pg-core';
import { authMethods, sessions } from './auth';
import { eventCategoryEnum, eventSeverityEnum } from './enum';
import { identities } from './identities';
import { organizations } from './organizations';

export const auditLogs = pgTable(
    'audit_logs',
    {
        id: uuid('id').primaryKey().defaultRandom(),
        organizationId: uuid('organization_id').references(
            () => organizations.id,
            { onDelete: 'set null' }
        ),

        // Actor (can be null for failed attempts)
        identityId: uuid('identity_id').references(() => identities.id, {
            onDelete: 'set null',
        }),
        sessionId: uuid('session_id').references(() => sessions.id, {
            onDelete: 'set null',
        }),
        authMethodId: uuid('auth_method_id').references(() => authMethods.id, {
            onDelete: 'set null',
        }),

        // Event
        eventType: varchar('event_type', { length: 127 }).notNull(), // "auth.login.success"
        eventCategory: eventCategoryEnum('event_category').notNull(),
        severity: eventSeverityEnum('severity').notNull(),

        // Client context
        ipAddress: inet('ip_address'),
        userAgent: text('user_agent'),

        // Affected resource
        resourceType: varchar('resource_type', { length: 63 }),
        resourceId: uuid('resource_id'),

        // Result
        success: boolean('success').notNull(),
        errorMessage: text('error_message'),
        errorCode: varchar('error_code', { length: 63 }),

        // Extensible metadata
        metadata: jsonb('metadata')
            .$type<Record<string, unknown>>()
            .default({})
            .notNull(),

        // Timestamp (immutable)
        createdAt: timestamp('created_at', { withTimezone: true })
            .notNull()
            .defaultNow(),
    },
    (table) => [
        // Timeline by organization (most frequent query)
        index('audit_log_org_created_idx').on(
            table.organizationId,
            table.createdAt.desc()
        ),

        // Timeline by identity
        index('audit_log_identity_created_idx')
            .on(table.identityId, table.createdAt.desc())
            .where(sql`${table.identityId} IS NOT NULL`),

        // Filtering by category and severity
        index('audit_log_category_severity_idx').on(
            table.organizationId,
            table.eventCategory,
            table.severity,
            table.createdAt.desc()
        ),

        // Search by event type
        index('audit_log_event_type_idx').on(
            table.organizationId,
            table.eventType,
            table.createdAt.desc()
        ),

        // Index for security incidents
        index('audit_log_security_critical_idx')
            .on(table.organizationId, table.createdAt.desc())
            .where(
                sql`${table.eventCategory} = 'security' OR ${table.severity} = 'critical'`
            ),

        // Index on IP for investigation
        index('audit_log_ip_idx')
            .on(table.ipAddress, table.createdAt.desc())
            .where(sql`${table.ipAddress} IS NOT NULL`),

        // Constraint: eventType format
        check(
            'audit_log_event_type_format',
            sql`${table.eventType} ~ '^[a-z]+\\.[a-z]+\\.[a-z]+$'`
        ),
    ]
);
