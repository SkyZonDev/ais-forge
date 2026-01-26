import type { ScheduledTask } from 'node-cron';
import cron from 'node-cron';
import nodemailer from 'nodemailer';
import { getAlertingConfig, getKeyRotationConfig } from '../../config/loader';
import {
    checkExpiringKeys,
    getKeyHealthStatus,
    purgeExpiredKeys,
    rotateSigningKey,
} from '../../core/keys/services';

export class KeyRotationScheduler {
    private config: ReturnType<typeof getKeyRotationConfig>;
    private alertingConfig: ReturnType<typeof getAlertingConfig>;
    private cronJob: ScheduledTask | null = null;

    constructor() {
        this.config = getKeyRotationConfig();
        this.alertingConfig = getAlertingConfig();
    }

    start(): void {
        if (!this.config.enabled) {
            console.info('Key rotation scheduler is disabled');
            return;
        }

        if (this.cronJob) {
            console.warn('Key rotation scheduler is already running');
            return;
        }

        this.cronJob = cron.schedule(this.config.schedule, async () => {
            await this.runRotationCheck();
        });

        console.info(
            `Key rotation scheduler started with schedule: ${this.config.schedule}`
        );
    }

    async runRotationCheck(): Promise<void> {
        console.info('Running scheduled key rotation check...');

        try {
            const healthStatus = await getKeyHealthStatus(
                this.config.thresholdDays
            );

            // Check for expiring keys and send alerts
            if (this.config.alerting?.enabled) {
                const alerts = await checkExpiringKeys(
                    this.config.alerting.expirationThresholdDays
                );

                if (alerts.length > 0) {
                    console.warn('Keys expiring soon:', { alerts });
                    await this.sendAlerts(alerts);
                }
            }

            // Perform automatic rotation if needed
            if (healthStatus.rotationRecommended) {
                console.info(
                    'Rotation recommended, initiating automatic rotation...'
                );

                const result = await rotateSigningKey({
                    reason: 'scheduled_auto_rotation',
                });

                console.info('Automatic key rotation completed', {
                    newKid: result.newKey.kid,
                    oldKid: result.oldKey.kid,
                });
            }

            // Purge expired keys
            if (this.config.autoPurge) {
                const purgedCount = await purgeExpiredKeys();

                if (purgedCount > 0) {
                    console.info(`Purged ${purgedCount} expired signing keys`);
                }
            }
        } catch (error) {
            console.error('Key rotation check failed:', error);
            throw error;
        }
    }

    protected async sendAlerts(alerts: string[]): Promise<void> {
        const promises: Promise<void>[] = [];

        // Slack alerts
        if (
            this.alertingConfig?.slack?.enabled &&
            this.alertingConfig.slack.webhookUrl
        ) {
            promises.push(this.sendSlackAlert(alerts));
        }

        // Email alerts
        if (this.alertingConfig?.email?.enabled) {
            promises.push(this.sendEmailAlert(alerts));
        }

        // PagerDuty alerts
        if (this.alertingConfig?.pagerduty?.enabled) {
            promises.push(this.sendPagerDutyAlert(alerts));
        }

        await Promise.allSettled(promises);
    }

    private async sendSlackAlert(alerts: string[]): Promise<void> {
        const webhookUrl = this.alertingConfig?.slack?.webhookUrl;
        if (!webhookUrl) return;

        const message = {
            channel: this.alertingConfig?.slack?.channel,
            username: 'AIS Forge Alert',
            icon_emoji: ':warning:',
            text: '⚠️ *Signing Key Expiration Alert*',
            attachments: [
                {
                    color: 'warning',
                    text: alerts.join('\n'),
                },
            ],
        };

        try {
            await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(message),
            });
            console.info('Slack alert sent successfully');
        } catch (error) {
            console.error('Failed to send Slack alert:', error);
        }
    }

    private async sendEmailAlert(alerts: string[]): Promise<void> {
        // Implementation using nodemailer
        const emailConfig = this.alertingConfig?.email;

        if (!emailConfig?.smtp || !emailConfig.to) return;

        const transporter = nodemailer.createTransport({
            host: emailConfig.smtp.host,
            port: emailConfig.smtp.port,
            secure: emailConfig.smtp.secure,
            auth: emailConfig.smtp.auth,
        });

        const mailOptions = {
            from: emailConfig.from,
            to: emailConfig.to.join(', '),
            subject: '⚠️ AIS Forge: Signing Key Expiration Alert',
            text: alerts.join('\n'),
            html: `
        <h2>⚠️ Signing Key Expiration Alert</h2>
        <ul>
          ${alerts.map((alert) => `<li>${alert}</li>`).join('')}
        </ul>
      `,
        };

        try {
            await transporter.sendMail(mailOptions);
            console.info('Email alert sent successfully');
        } catch (error) {
            console.error('Failed to send email alert:', error);
        }
    }

    private async sendPagerDutyAlert(alerts: string[]): Promise<void> {
        // Implementation for PagerDuty Events API v2
        const integrationKey = this.alertingConfig?.pagerduty?.integrationKey;
        if (!integrationKey) return;

        const payload = {
            routing_key: integrationKey,
            event_action: 'trigger',
            payload: {
                summary: 'Signing keys expiring soon',
                severity: 'warning',
                source: 'ais-forge',
                custom_details: {
                    alerts: alerts,
                },
            },
        };

        try {
            await fetch('https://events.pagerduty.com/v2/enqueue', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            console.info('PagerDuty alert sent successfully');
        } catch (error) {
            console.error('Failed to send PagerDuty alert:', error);
        }
    }
}

// Export singleton with config
export const keyRotationScheduler = new KeyRotationScheduler();
