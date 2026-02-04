import type { ScheduledTask } from 'node-cron';
import cron from 'node-cron';
import { getAlertingConfig, getTokenCleanupConfig } from '../../config/loader';
import { refreshTokenRepository } from '../../db/repository/refresh-token.repository';
import { sessionsRepository } from '../../db/repository/session.repository';

// ============================================================================
// TYPES
// ============================================================================

interface CleanupThresholds {
    /** Days after revocation before a session record is hard-deleted */
    revokedSessionDays: number;
    /** Days after expiration before a session record is hard-deleted */
    expiredSessionDays: number;
    /** Days after revocation before a refresh-token record is hard-deleted */
    revokedTokenDays: number;
    /** Days after expiration before a refresh-token record is hard-deleted */
    expiredTokenDays: number;
    /** Days after use (rotation) before a refresh-token record is hard-deleted */
    usedTokenDays: number;
}

interface CleanupReport {
    startedAt: Date;
    completedAt: Date;
    sessions: {
        revokedDeleted: number;
        expiredDeleted: number;
    };
    refreshTokens: {
        revokedDeleted: number;
        expiredDeleted: number;
        usedDeleted: number;
    };
    cacheCleared: boolean;
    errors: string[];
}

// ============================================================================
// HELPERS
// ============================================================================

/**
 * Builds a Date offset by a given number of days into the past.
 */
function daysAgo(days: number): Date {
    return new Date(Date.now() - days * 24 * 60 * 60 * 1000);
}

// ============================================================================
// SCHEDULER
// ============================================================================

export class TokenCleanupScheduler {
    private config: ReturnType<typeof getTokenCleanupConfig>;
    private alertingConfig: ReturnType<typeof getAlertingConfig>;
    private cronJob: ScheduledTask | null = null;

    constructor() {
        this.config = getTokenCleanupConfig();
        this.alertingConfig = getAlertingConfig();
    }

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    start(): void {
        if (!this.config.enabled) {
            console.info('Token cleanup scheduler is disabled');
            return;
        }

        if (this.cronJob) {
            console.warn('Token cleanup scheduler is already running');
            return;
        }

        this.cronJob = cron.schedule(this.config.schedule, async () => {
            await this.runCleanup();
        });

        console.info(
            `Token cleanup scheduler started with schedule: ${this.config.schedule}`
        );
    }

    stop(): void {
        if (this.cronJob) {
            this.cronJob.stop();
            this.cronJob = null;
            console.info('Token cleanup scheduler stopped');
        }
    }

    // ========================================================================
    // CLEANUP ORCHESTRATION
    // ========================================================================

    /**
     * Runs the full cleanup cycle: sessions, refresh tokens, then cache.
     *
     * Each phase is isolated in its own try/catch so that a failure in one
     * does not prevent the others from executing. All errors are collected
     * and reported together at the end.
     */
    async runCleanup(): Promise<CleanupReport> {
        const startedAt = new Date();
        console.info('Running scheduled token cleanup...');

        const report: CleanupReport = {
            startedAt,
            completedAt: startedAt, // overwritten below
            sessions: { revokedDeleted: 0, expiredDeleted: 0 },
            refreshTokens: {
                revokedDeleted: 0,
                expiredDeleted: 0,
                usedDeleted: 0,
            },
            cacheCleared: false,
            errors: [],
        };

        const thresholds = this.getThresholds();

        // --- Sessions ---
        try {
            report.sessions = await this.cleanupSessions(thresholds);
        } catch (error) {
            const message =
                error instanceof Error ? error.message : String(error);
            console.error('Session cleanup phase failed:', error);
            report.errors.push(`sessions: ${message}`);
        }

        // --- Refresh tokens ---
        try {
            report.refreshTokens = await this.cleanupRefreshTokens(thresholds);
        } catch (error) {
            const message =
                error instanceof Error ? error.message : String(error);
            console.error('Refresh-token cleanup phase failed:', error);
            report.errors.push(`refresh_tokens: ${message}`);
        }

        // --- Redis cache ---
        try {
            if (this.config.invalidateCacheOnCleanup) {
                await sessionsRepository.clearAllCache();
                await refreshTokenRepository.clearAllCache();
                report.cacheCleared = true;
                console.info('Redis caches invalidated after cleanup');
            }
        } catch (error) {
            const message =
                error instanceof Error ? error.message : String(error);
            console.error('Cache invalidation failed:', error);
            report.errors.push(`cache: ${message}`);
        }

        report.completedAt = new Date();

        this.logReport(report);

        // --- Alerts (fire-and-forget, never blocks the scheduler) ---
        if (this.config.alerting?.enabled) {
            this.sendCleanupReport(report).catch((err) =>
                console.error('Failed to send cleanup alert:', err)
            );
        }

        return report;
    }

    // ========================================================================
    // PHASE IMPLEMENTATIONS
    // ========================================================================

    /**
     * Deletes revoked and expired session records that are older than the
     * configured thresholds.
     */
    private async cleanupSessions(
        thresholds: CleanupThresholds
    ): Promise<CleanupReport['sessions']> {
        const revokedDeleted = await sessionsRepository.deleteRevokedBefore(
            daysAgo(thresholds.revokedSessionDays)
        );

        const expiredDeleted = await sessionsRepository.deleteExpiredBefore(
            daysAgo(thresholds.expiredSessionDays)
        );

        if (revokedDeleted > 0 || expiredDeleted > 0) {
            console.info('Sessions cleaned up', {
                revokedDeleted,
                expiredDeleted,
            });
        }

        return { revokedDeleted, expiredDeleted };
    }

    /**
     * Deletes revoked, expired, and used (rotated) refresh-token records that
     * are older than the configured thresholds.
     *
     * Used tokens are kept longer by default because they are needed for
     * refresh-token-theft detection (reuse of a rotated token triggers a
     * family-wide revocation).
     */
    private async cleanupRefreshTokens(
        thresholds: CleanupThresholds
    ): Promise<CleanupReport['refreshTokens']> {
        const revokedDeleted = await refreshTokenRepository.deleteRevokedBefore(
            daysAgo(thresholds.revokedTokenDays)
        );

        const expiredDeleted = await refreshTokenRepository.deleteExpiredBefore(
            daysAgo(thresholds.expiredTokenDays)
        );

        const usedDeleted = await refreshTokenRepository.deleteUsedBefore(
            daysAgo(thresholds.usedTokenDays)
        );

        if (revokedDeleted > 0 || expiredDeleted > 0 || usedDeleted > 0) {
            console.info('Refresh tokens cleaned up', {
                revokedDeleted,
                expiredDeleted,
                usedDeleted,
            });
        }

        return { revokedDeleted, expiredDeleted, usedDeleted };
    }

    // ========================================================================
    // CONFIG HELPERS
    // ========================================================================

    /**
     * Resolves the effective thresholds, falling back to safe defaults.
     *
     * Used-token retention is deliberately longer (90 d) so that the
     * token-family theft-detection window is not shortened prematurely.
     */
    private getThresholds(): CleanupThresholds {
        return {
            revokedSessionDays:
                this.config.thresholds?.revokedSessionDays ?? 30,
            expiredSessionDays: this.config.thresholds?.expiredSessionDays ?? 7,
            revokedTokenDays: this.config.thresholds?.revokedTokenDays ?? 30,
            expiredTokenDays: this.config.thresholds?.expiredTokenDays ?? 7,
            usedTokenDays: this.config.thresholds?.usedTokenDays ?? 90,
        };
    }

    // ========================================================================
    // LOGGING
    // ========================================================================

    private logReport(report: CleanupReport): void {
        const totalDeleted =
            report.sessions.revokedDeleted +
            report.sessions.expiredDeleted +
            report.refreshTokens.revokedDeleted +
            report.refreshTokens.expiredDeleted +
            report.refreshTokens.usedDeleted;

        const durationMs =
            report.completedAt.getTime() - report.startedAt.getTime();

        console.info('Token cleanup completed', {
            durationMs,
            totalDeleted,
            sessions: report.sessions,
            refreshTokens: report.refreshTokens,
            cacheCleared: report.cacheCleared,
            errors: report.errors.length > 0 ? report.errors : undefined,
        });
    }

    // ========================================================================
    // ALERTING
    // ========================================================================

    /**
     * Dispatches the cleanup report to all enabled alert channels.
     * Uses Promise.allSettled so that one failing channel does not
     * prevent the others from being notified.
     */
    protected async sendCleanupReport(report: CleanupReport): Promise<void> {
        const promises: Promise<void>[] = [];

        if (
            this.alertingConfig?.slack?.enabled &&
            this.alertingConfig.slack.webhookUrl
        ) {
            promises.push(this.sendSlackReport(report));
        }

        if (this.alertingConfig?.email?.enabled) {
            promises.push(this.sendEmailReport(report));
        }

        if (
            this.alertingConfig?.pagerduty?.enabled &&
            report.errors.length > 0
        ) {
            promises.push(this.sendPagerDutyAlert(report));
        }

        await Promise.allSettled(promises);
    }

    private async sendSlackReport(report: CleanupReport): Promise<void> {
        const webhookUrl = this.alertingConfig?.slack?.webhookUrl;
        if (!webhookUrl) return;

        const totalDeleted =
            report.sessions.revokedDeleted +
            report.sessions.expiredDeleted +
            report.refreshTokens.revokedDeleted +
            report.refreshTokens.expiredDeleted +
            report.refreshTokens.usedDeleted;

        const status =
            report.errors.length === 0 ? ':white_check_mark:' : ':warning:';

        const message = {
            channel: this.alertingConfig?.slack?.channel,
            username: 'AIS Forge Alert',
            icon_emoji: ':broom:',
            text: `${status} *Token Cleanup Report*`,
            attachments: [
                {
                    color: report.errors.length === 0 ? 'good' : 'warning',
                    fields: [
                        {
                            title: 'Total Deleted',
                            value: String(totalDeleted),
                            short: true,
                        },
                        {
                            title: 'Duration',
                            value: `${report.completedAt.getTime() - report.startedAt.getTime()} ms`,
                            short: true,
                        },
                        {
                            title: 'Sessions (revoked / expired)',
                            value: `${report.sessions.revokedDeleted} / ${report.sessions.expiredDeleted}`,
                            short: true,
                        },
                        {
                            title: 'Tokens (revoked / expired / used)',
                            value: `${report.refreshTokens.revokedDeleted} / ${report.refreshTokens.expiredDeleted} / ${report.refreshTokens.usedDeleted}`,
                            short: true,
                        },
                        ...(report.errors.length > 0
                            ? [
                                  {
                                      title: 'Errors',
                                      value: report.errors.join('\n'),
                                      short: false,
                                  },
                              ]
                            : []),
                    ],
                },
            ],
        };

        try {
            await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(message),
            });
            console.info('Slack cleanup report sent successfully');
        } catch (error) {
            console.error('Failed to send Slack cleanup report:', error);
        }
    }

    private async sendEmailReport(report: CleanupReport): Promise<void> {
        const nodemailer = await import('nodemailer');
        const emailConfig = this.alertingConfig?.email;

        if (!emailConfig?.smtp || !emailConfig.to) return;

        const totalDeleted =
            report.sessions.revokedDeleted +
            report.sessions.expiredDeleted +
            report.refreshTokens.revokedDeleted +
            report.refreshTokens.expiredDeleted +
            report.refreshTokens.usedDeleted;

        const transporter = nodemailer.createTransport({
            host: emailConfig.smtp.host,
            port: emailConfig.smtp.port,
            secure: emailConfig.smtp.secure,
            auth: emailConfig.smtp.auth,
        });

        const errorsHtml =
            report.errors.length > 0
                ? `<h3 style="color:#e53e3e">⚠️ Errors</h3>
               <ul>${report.errors.map((e) => `<li><code>${e}</code></li>`).join('')}</ul>`
                : '';

        const mailOptions = {
            from: emailConfig.from,
            to: emailConfig.to.join(', '),
            subject: `AIS Forge: Token Cleanup — ${totalDeleted} record${totalDeleted !== 1 ? 's' : ''} deleted`,
            text: [
                'Token Cleanup Report',
                `Started:   ${report.startedAt.toISOString()}`,
                `Completed: ${report.completedAt.toISOString()}`,
                '',
                'Sessions',
                `  Revoked deleted: ${report.sessions.revokedDeleted}`,
                `  Expired deleted: ${report.sessions.expiredDeleted}`,
                '',
                'Refresh Tokens',
                `  Revoked deleted: ${report.refreshTokens.revokedDeleted}`,
                `  Expired deleted: ${report.refreshTokens.expiredDeleted}`,
                `  Used deleted:    ${report.refreshTokens.usedDeleted}`,
                '',
                ...(report.errors.length > 0
                    ? ['Errors:', ...report.errors.map((e) => `  - ${e}`)]
                    : []),
            ].join('\n'),
            html: `
                <h2>🧹 Token Cleanup Report</h2>
                <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-family:monospace">
                  <tr><th>Category</th><th>Revoked</th><th>Expired</th><th>Used</th></tr>
                  <tr>
                    <td>Sessions</td>
                    <td>${report.sessions.revokedDeleted}</td>
                    <td>${report.sessions.expiredDeleted}</td>
                    <td>—</td>
                  </tr>
                  <tr>
                    <td>Refresh Tokens</td>
                    <td>${report.refreshTokens.revokedDeleted}</td>
                    <td>${report.refreshTokens.expiredDeleted}</td>
                    <td>${report.refreshTokens.usedDeleted}</td>
                  </tr>
                </table>
                <p><strong>Duration:</strong> ${report.completedAt.getTime() - report.startedAt.getTime()} ms</p>
                <p><strong>Cache invalidated:</strong> ${report.cacheCleared ? 'Yes' : 'No'}</p>
                ${errorsHtml}
            `,
        };

        try {
            await transporter.sendMail(mailOptions);
            console.info('Email cleanup report sent successfully');
        } catch (error) {
            console.error('Failed to send email cleanup report:', error);
        }
    }

    /**
     * PagerDuty alert is only triggered when at least one cleanup phase
     * errored out — a fully successful run is not an incident.
     */
    private async sendPagerDutyAlert(report: CleanupReport): Promise<void> {
        const integrationKey = this.alertingConfig?.pagerduty?.integrationKey;
        if (!integrationKey) return;

        const payload = {
            routing_key: integrationKey,
            event_action: 'trigger',
            payload: {
                summary: `Token cleanup encountered ${report.errors.length} error(s)`,
                severity: 'warning',
                source: 'ais-forge',
                custom_details: {
                    errors: report.errors,
                    sessions: report.sessions,
                    refreshTokens: report.refreshTokens,
                    startedAt: report.startedAt.toISOString(),
                    completedAt: report.completedAt.toISOString(),
                },
            },
        };

        try {
            await fetch('https://events.pagerduty.com/v2/enqueue', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            console.info('PagerDuty cleanup alert sent successfully');
        } catch (error) {
            console.error('Failed to send PagerDuty cleanup alert:', error);
        }
    }
}

// ============================================================================
// SINGLETON
// ============================================================================

export const tokenCleanupScheduler = new TokenCleanupScheduler();
