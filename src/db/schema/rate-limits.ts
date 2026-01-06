import { sql } from 'drizzle-orm';
import {
    check,
    index,
    integer,
    interval,
    pgTable,
    timestamp,
    uniqueIndex,
    uuid,
    varchar,
} from 'drizzle-orm/pg-core';
import { identities } from './identities';
import { organizations } from './organizations';

export const rateLimits = pgTable(
    'rate_limits',
    {
        id: uuid('id').primaryKey().defaultRandom(),

        // Contexte (optionnel)
        organizationId: uuid('organization_id').references(
            () => organizations.id,
            { onDelete: 'cascade' }
        ),
        identityId: uuid('identity_id').references(() => identities.id, {
            onDelete: 'cascade',
        }),

        // Clé de rate limit: "login:ip:1.2.3.4" ou "api:identity:uuid"
        key: varchar('key', { length: 255 }).notNull(),

        // Fenêtre temporelle
        windowStart: timestamp('window_start', {
            withTimezone: true,
        }).notNull(),
        windowDuration: interval('window_duration').notNull(),

        // Compteur
        attemptCount: integer('attempt_count').notNull().default(0),
        lastAttemptAt: timestamp('last_attempt_at', {
            withTimezone: true,
        }).notNull(),

        // Blocage temporaire
        blockedUntil: timestamp('blocked_until', { withTimezone: true }),
    },
    (table) => [
        // Lookup principal: clé + fenêtre
        uniqueIndex('rate_limit_key_window_unique_idx').on(
            table.key,
            table.windowStart
        ),

        // Entrées bloquées (pour vérification rapide)
        index('rate_limit_blocked_idx')
            .on(table.blockedUntil)
            .where(
                sql`${table.blockedUntil} IS NOT NULL AND ${table.blockedUntil} > NOW()`
            ),

        // Cleanup des anciennes fenêtres
        index('rate_limit_window_start_idx').on(table.windowStart),

        // Contrainte: compteur positif
        check('rate_limit_count_positive', sql`${table.attemptCount} >= 0`),
    ]
);
