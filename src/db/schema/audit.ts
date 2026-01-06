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
        organizationId: uuid('organization_id')
            .notNull()
            .references(() => organizations.id, { onDelete: 'cascade' }),

        // Acteur (peut être null pour tentatives échouées)
        identityId: uuid('identity_id').references(() => identities.id, {
            onDelete: 'set null',
        }),
        sessionId: uuid('session_id').references(() => sessions.id, {
            onDelete: 'set null',
        }),
        authMethodId: uuid('auth_method_id').references(() => authMethods.id, {
            onDelete: 'set null',
        }),

        // Événement
        eventType: varchar('event_type', { length: 127 }).notNull(), // "auth.login.success"
        eventCategory: eventCategoryEnum('event_category').notNull(),
        severity: eventSeverityEnum('severity').notNull(),

        // Contexte client
        ipAddress: inet('ip_address'),
        userAgent: text('user_agent'),

        // Ressource affectée
        resourceType: varchar('resource_type', { length: 63 }),
        resourceId: uuid('resource_id'),

        // Résultat
        success: boolean('success').notNull(),
        errorMessage: text('error_message'),
        errorCode: varchar('error_code', { length: 63 }),

        // Metadata extensible
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
        // Timeline par organisation (requête la plus fréquente)
        index('audit_log_org_created_idx').on(
            table.organizationId,
            table.createdAt.desc()
        ),

        // Timeline par identité
        index('audit_log_identity_created_idx')
            .on(table.identityId, table.createdAt.desc())
            .where(sql`${table.identityId} IS NOT NULL`),

        // Filtrage par catégorie et sévérité
        index('audit_log_category_severity_idx').on(
            table.organizationId,
            table.eventCategory,
            table.severity,
            table.createdAt.desc()
        ),

        // Recherche par type d'événement
        index('audit_log_event_type_idx').on(
            table.organizationId,
            table.eventType,
            table.createdAt.desc()
        ),

        // Index pour les incidents de sécurité
        index('audit_log_security_critical_idx')
            .on(table.organizationId, table.createdAt.desc())
            .where(
                sql`${table.eventCategory} = 'security' OR ${table.severity} = 'critical'`
            ),

        // Index sur IP pour investigation
        index('audit_log_ip_idx')
            .on(table.ipAddress, table.createdAt.desc())
            .where(sql`${table.ipAddress} IS NOT NULL`),

        // Contrainte: eventType format
        check(
            'audit_log_event_type_format',
            sql`${table.eventType} ~ '^[a-z]+\\.[a-z]+\\.[a-z]+$'`
        ),
    ]
);
