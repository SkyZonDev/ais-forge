#!/usr/bin/env node
// biome-ignore-all lint: main script

/**
 * AIS Forge Configuration Management CLI
 *
 * Usage:
 *   npm run config validate              - Validate configuration
 *   npm run config generate-key          - Generate master encryption key
 *   npm run config show                  - Show current config (safe)
 *   npm run config export-env            - Export to .env format
 *   npm run config merge dev prod        - Merge configs
 */

import { randomBytes } from 'crypto';
import { readFileSync, writeFileSync } from 'fs';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { configLoader } from '../src/config/loader';

const command = process.argv[2];
const args = process.argv.slice(3);

// ============================================================================
// COMMANDS
// ============================================================================

async function validateConfig() {
    console.log('🔍 Validating configuration...\n');

    try {
        const config = configLoader.load();

        console.log('✅ Configuration is valid!\n');
        console.log('Summary:');
        console.log(`  • Server: ${config.server.host}:${config.server.port}`);
        console.log(`  • Database configured: ✓`);
        console.log(`  • Master key configured: ✓`);
        console.log(
            `  • Key rotation: ${config.keyRotation.enabled ? 'enabled' : 'disabled'}`
        );
        console.log(
            `  • Metrics: ${config.metrics?.enabled ? 'enabled' : 'disabled'}`
        );

        if (config.alerting?.slack?.enabled) {
            console.log(
                `  • Slack alerts: enabled (${config.alerting.slack.channel || 'default'})`
            );
        }
        if (config.alerting?.email?.enabled) {
            console.log(
                `  • Email alerts: enabled (${config.alerting.email.to?.length || 0} recipients)`
            );
        }

        process.exit(0);
    } catch (error) {
        console.error('❌ Configuration validation failed:\n');
        console.error(error);
        process.exit(1);
    }
}

function generateMasterKey() {
    console.log('🔑 Generating master encryption key...\n');

    const key = randomBytes(32).toString('base64');

    console.log('Master Encryption Key (base64):');
    console.log('━'.repeat(60));
    console.log(key);
    console.log('━'.repeat(60));
    console.log('\n⚠️  IMPORTANT: Store this key securely!');
    console.log('   • Add to your .env file: MASTER_ENCRYPTION_KEY=' + key);
    console.log(
        '   • For Kubernetes: kubectl create secret generic aisforge-secrets \\'
    );
    console.log('       --from-literal=master-encryption-key=' + key);
    console.log('   • For Docker: Pass as environment variable');
    console.log('\n🔒 Never commit this key to version control!');
}

function showConfig() {
    console.log('📋 Current Configuration\n');

    try {
        const config = configLoader.load();

        // Remove sensitive data
        const safeConfig = {
            ...config,
            security: {
                ...config.security,
                masterEncryptionKey: '***REDACTED***',
            },
            database: {
                ...config.database,
                url: config.database.url.replace(/:[^:@]+@/, ':***@'),
            },
            alerting: config.alerting
                ? {
                      slack: config.alerting.slack
                          ? {
                                ...config.alerting.slack,
                                webhookUrl: config.alerting.slack.webhookUrl
                                    ? '***REDACTED***'
                                    : undefined,
                            }
                          : undefined,
                      email: config.alerting.email
                          ? {
                                ...config.alerting.email,
                                smtp: config.alerting.email.smtp
                                    ? {
                                          ...config.alerting.email.smtp,
                                          auth: {
                                              user: config.alerting.email.smtp
                                                  .auth?.user,
                                              pass: '***REDACTED***',
                                          },
                                      }
                                    : undefined,
                            }
                          : undefined,
                      pagerduty: config.alerting.pagerduty
                          ? {
                                ...config.alerting.pagerduty,
                                integrationKey: '***REDACTED***',
                            }
                          : undefined,
                  }
                : undefined,
        };

        console.log(stringifyYaml(safeConfig));
    } catch (error) {
        console.error('❌ Failed to load configuration:', error);
        process.exit(1);
    }
}

function exportToEnv() {
    console.log('📤 Exporting configuration to .env format\n');

    try {
        const config = configLoader.load();

        const envVars = [
            '# AIS Forge - Generated Environment Variables',
            '# Generated at: ' + new Date().toISOString(),
            '',
            '# Server',
            `PORT=${config.server.port}`,
            `HOST=${config.server.host}`,
            `PUBLIC_URL=${config.server.publicUrl || ''}`,
            '',
            '# Database',
            `DATABASE_URL=${config.database.url}`,
            `DATABASE_SSL=${config.database.ssl}`,
            '',
            '# Security',
            `MASTER_ENCRYPTION_KEY=${config.security.masterEncryptionKey}`,
            `JWT_ISSUER=${config.security.jwt.issuer}`,
            `JWT_AUDIENCE=${config.security.jwt.audience}`,
            `ACCESS_TOKEN_TTL=${config.security.jwt.accessTokenTTL}`,
            `REFRESH_TOKEN_TTL_DAYS=${config.security.refreshToken.ttlDays}`,
            '',
            '# Key Rotation',
            `KEY_ROTATION_ENABLED=${config.keyRotation.enabled}`,
            `KEY_ROTATION_SCHEDULE=${config.keyRotation.schedule}`,
            `KEY_ROTATION_THRESHOLD=${config.keyRotation.thresholdDays}`,
            `KEY_AUTO_PURGE=${config.keyRotation.autoPurge}`,
            '',
            '# Logging',
            `LOG_LEVEL=${config.logging.level}`,
            `LOG_FORMAT=${config.logging.format}`,
            '',
        ];

        if (config.alerting?.slack?.enabled) {
            envVars.push('# Slack Alerts');
            envVars.push('SLACK_ENABLED=true');
            envVars.push(
                `SLACK_WEBHOOK_URL=${config.alerting.slack.webhookUrl || ''}`
            );
            envVars.push(
                `SLACK_CHANNEL=${config.alerting.slack.channel || ''}`
            );
            envVars.push('');
        }

        if (config.metrics?.enabled) {
            envVars.push('# Metrics');
            envVars.push('METRICS_ENABLED=true');
            envVars.push(`METRICS_PORT=${config.metrics.port}`);
            envVars.push(`METRICS_PATH=${config.metrics.path}`);
            envVars.push('');
        }

        const output = envVars.join('\n');

        const filename = `.env.generated`;
        writeFileSync(filename, output);

        console.log(`✅ Environment variables exported to: ${filename}`);
        console.log(
            '\n⚠️  Review the file and remove any sensitive data before committing!'
        );
    } catch (error) {
        console.error('❌ Failed to export configuration:', error);
        process.exit(1);
    }
}

function mergeConfigs() {
    if (args.length < 2) {
        console.error(
            '❌ Usage: npm run config merge <base-config> <override-config>'
        );
        console.error(
            '   Example: npm run config merge config.yaml config.production.yaml'
        );
        process.exit(1);
    }

    const [baseFile, overrideFile] = args as [string, string];

    console.log(`🔀 Merging configurations...\n`);
    console.log(`   Base: ${baseFile}`);
    console.log(`   Override: ${overrideFile}\n`);

    try {
        const baseContent = readFileSync(baseFile, 'utf-8');
        const overrideContent = readFileSync(overrideFile, 'utf-8');

        const baseConfig = parseYaml(baseContent);
        const overrideConfig = parseYaml(overrideContent);

        // Deep merge
        const merged = deepMerge(baseConfig, overrideConfig);

        const outputFile = 'config.merged.yaml';
        writeFileSync(outputFile, stringifyYaml(merged));

        console.log(`✅ Merged configuration saved to: ${outputFile}`);
    } catch (error) {
        console.error('❌ Failed to merge configurations:', error);
        process.exit(1);
    }
}

// ============================================================================
// HELPERS
// ============================================================================

function deepMerge(target: any, source: any): any {
    const output = { ...target };

    if (isObject(target) && isObject(source)) {
        Object.keys(source).forEach((key) => {
            if (isObject(source[key])) {
                if (!(key in target)) {
                    Object.assign(output, { [key]: source[key] });
                } else {
                    output[key] = deepMerge(target[key], source[key]);
                }
            } else {
                Object.assign(output, { [key]: source[key] });
            }
        });
    }

    return output;
}

function isObject(item: any): boolean {
    return item && typeof item === 'object' && !Array.isArray(item);
}

// ============================================================================
// CLI ROUTER
// ============================================================================

async function main() {
    switch (command) {
        case 'validate':
            await validateConfig();
            break;

        case 'generate-key':
            generateMasterKey();
            break;

        case 'show':
            showConfig();
            break;

        case 'export-env':
            exportToEnv();
            break;

        case 'merge':
            mergeConfigs();
            break;

        default:
            console.log('AIS Forge Configuration Management CLI\n');
            console.log('Available commands:');
            console.log('  validate      - Validate configuration');
            console.log('  generate-key  - Generate master encryption key');
            console.log('  show          - Show current config (redacted)');
            console.log('  export-env    - Export to .env format');
            console.log('  merge         - Merge two config files');
            console.log('\nUsage: npm run config <command> [args]');
            process.exit(1);
    }
}

main().catch((error) => {
    console.error('Unexpected error:', error);
    process.exit(1);
});
