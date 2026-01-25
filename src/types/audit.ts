import { eventCategory, eventSeverity } from '../db/schema/enum';

type EventCategory = (typeof eventCategory)[number];
type EventSeverity = (typeof eventSeverity)[number];

/** Options de filtrage pour les logs */
interface AuditLogFilterOptions {
    startDate?: Date;
    endDate?: Date;
    eventCategory?: EventCategory;
    severity?: EventSeverity;
    eventType?: string;
    success?: boolean;
    ipAddress?: string;
    identityId?: string;
    resourceType?: string;
    resourceId?: string;
}

/** Données pour créer un log */
interface CreateAuditLogData {
    organizationId?: string;
    identityId?: string;
    sessionId?: string;
    authMethodId?: string;
    eventType: string;
    eventCategory: EventCategory;
    severity: EventSeverity;
    ipAddress?: string;
    userAgent?: string;
    resourceType?: string;
    resourceId?: string;
    success: boolean;
    errorMessage?: string;
    errorCode?: string;
    metadata?: Record<string, unknown>;
}

export type {
    EventCategory,
    EventSeverity,
    AuditLogFilterOptions,
    CreateAuditLogData,
};
