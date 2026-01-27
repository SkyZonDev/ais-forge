import 'dotenv/config';
import fs, { readFileSync } from 'fs';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { signingAlgorithm } from '../db';

// ============================================================================
// CONFIGURATION SCHEMA WITH ZOD VALIDATION
// ============================================================================

const SigningAlgorithmSchema = z.enum(signingAlgorithm);

const ServerConfigSchema = z.object({
    port: z.number().int().min(1).max(65535).default(3000),
    host: z.string().default('0.0.0.0'),
    publicUrl: z.url().optional(),
    cors: z.object({
        enabled: z.boolean().default(true),
        origins: z.array(z.string()).default(['*']),
        credentials: z.boolean().default(true),
    }),
    rateLimit: z.object({
        enabled: z.boolean().default(true),
        max: z.number().int().min(1).default(100),
        timeWindow: z.string().default('1m'),
    }),
});

const DatabaseConfigSchema = z.object({
    url: z.string().min(1),
    pool: z
        .object({
            min: z.number().int().min(0).default(2),
            max: z.number().int().min(1).default(10),
        })
        .optional(),
    ssl: z.boolean().default(false),
});

const RedisConfigSchema = z.object({
    url: z.string().min(1),
});

const SecurityConfigSchema = z.object({
    masterEncryptionKey: z.string().min(1),
    jwt: z.object({
        issuer: z.string().default('ais-forge'),
        audience: z.string().default('api'),
        accessTokenTTL: z.string().default('15m'),
    }),
    refreshToken: z.object({
        ttlDays: z.number().int().min(1).max(365).default(30),
    }),
    defaultAlgorithm: SigningAlgorithmSchema.default('ES256'),
});

const KeyRotationConfigSchema = z.object({
    enabled: z.boolean().default(true),
    schedule: z.string().default('0 2 * * *'),
    thresholdDays: z.number().int().min(1).max(365).default(30),
    autoPurge: z.boolean().default(true),
    alerting: z.object({
        enabled: z.boolean().default(true),
        expirationThresholdDays: z.number().int().min(1).default(14),
    }),
});

const LoggingConfigSchema = z.object({
    level: z
        .enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal'])
        .default('info'),
    format: z.enum(['json', 'pretty']).default('json'),
    redactSensitive: z.boolean().default(true),
});

const AlertingConfigSchema = z.object({
    slack: z
        .object({
            enabled: z.boolean().default(false),
            webhookUrl: z.url().optional(),
            channel: z.string().optional(),
        })
        .optional(),
    email: z
        .object({
            enabled: z.boolean().default(false),
            smtp: z
                .object({
                    host: z.string().optional(),
                    port: z.number().int().min(1).max(65535).optional(),
                    secure: z.boolean().default(true),
                    auth: z
                        .object({
                            user: z.string().optional(),
                            pass: z.string().optional(),
                        })
                        .optional(),
                })
                .optional(),
            from: z.email().optional(),
            to: z.array(z.email()).optional(),
        })
        .optional(),
    pagerduty: z
        .object({
            enabled: z.boolean().default(false),
            integrationKey: z.string().optional(),
        })
        .optional(),
});

const FeaturesConfigSchema = z.object({
    introspection: z.boolean().default(true),
    openidConfig: z.boolean().default(true),
    adminApi: z.boolean().default(true),
    multiAlgorithm: z.boolean().default(false),
});

const MetricsConfigSchema = z.object({
    enabled: z.boolean().default(false),
    port: z.number().int().min(1).max(65535).default(9090),
    path: z.string().default('/metrics'),
    prometheus: z.boolean().default(true),
});

// Main configuration schema
const ConfigSchema = z.object({
    server: ServerConfigSchema,
    database: DatabaseConfigSchema,
    redis: RedisConfigSchema,
    security: SecurityConfigSchema,
    keyRotation: KeyRotationConfigSchema,
    logging: LoggingConfigSchema,
    alerting: AlertingConfigSchema.optional(),
    features: FeaturesConfigSchema,
    metrics: MetricsConfigSchema.optional(),
    isProduction: z.boolean().default(false),
});

export type AppConfig = z.infer<typeof ConfigSchema>;

// ============================================================================
// CONFIGURATION LOADER
// ============================================================================

export class ConfigLoader {
    private config: AppConfig | null = null;

    /**
     * Load configuration from multiple sources with priority:
     * 1. Environment variables (highest priority)
     * 2. Config file (YAML/JSON)
     * 3. Default values (lowest priority)
     */
    load(): AppConfig {
        if (this.config) {
            return this.config;
        }

        // 1. Determine config file path
        const configPath = process.env.CONFIG_FILE || this.detectConfigFile();

        // 2. Load base config from file
        let fileConfig: Partial<AppConfig> = {};

        if (configPath) {
            try {
                fileConfig = this.loadConfigFile(configPath);
                console.log(`Loaded configuration from: ${configPath}`);
            } catch (error) {
                console.warn(
                    `Failed to load config file: ${configPath}`,
                    error
                );
            }
        }

        // 3. Merge with environment variables
        const mergedConfig = this.mergeWithEnv(fileConfig);

        // 4. Validate with Zod
        try {
            this.config = ConfigSchema.parse(mergedConfig);
            console.log('Configuration validated successfully');
            return this.config;
        } catch (error) {
            if (error instanceof z.ZodError) {
                console.error('Configuration validation failed:');
                error.issues.forEach((err) => {
                    console.error(`  - ${err.path.join('.')}: ${err.message}`);
                });
            }
            throw new Error('Invalid configuration');
        }
    }

    /**
     * Auto-detect config file in order of preference
     */
    private detectConfigFile(): string | null {
        const candidates = [
            'config.yaml',
            'config.yml',
            'config.json',
            'config/config.yaml',
            'config/config.yml',
            'config/config.json',
        ];

        for (const file of candidates) {
            if (fs.existsSync(file)) {
                return file;
            }
        }

        return null;
    }

    /**
     * Load and parse config file (YAML or JSON)
     */
    private loadConfigFile(path: string): Partial<AppConfig> {
        const content = readFileSync(path, 'utf-8');

        let parsed: Partial<AppConfig>;
        if (
            path.endsWith('.yaml') ||
            (path.endsWith('.yml') && !path.includes('example'))
        ) {
            parsed = parseYaml(content) as Partial<AppConfig>;
        } else if (path.endsWith('.json')) {
            parsed = JSON.parse(content) as Partial<AppConfig>;
        } else {
            throw new Error(`Unsupported config file format: ${path}`);
        }

        // Interpolate environment variables
        return this.interpolateEnvVars(parsed);
    }

    /**
     * Recursively interpolate environment variables in config object
     * Replaces ${VAR_NAME} with process.env.VAR_NAME
     */
    private interpolateEnvVars<T>(obj: T): T {
        if (typeof obj === 'string') {
            // Replace ${VAR_NAME} or $VAR_NAME with environment variable
            return obj.replace(
                /\$\{([^}]+)\}|\$([A-Z_][A-Z0-9_]*)/g,
                (match, varName1, varName2) => {
                    const varName = varName1 || varName2;
                    const value = process.env[varName];
                    if (value === undefined) {
                        console.warn(
                            `Environment variable ${varName} not found, keeping placeholder`
                        );
                        return match;
                    }
                    return value;
                }
            ) as T;
        }

        if (Array.isArray(obj)) {
            return obj.map((item) => this.interpolateEnvVars(item)) as T;
        }

        if (obj !== null && typeof obj === 'object') {
            const result = {} as T;
            for (const [key, value] of Object.entries(obj)) {
                (result as Record<string, unknown>)[key] =
                    this.interpolateEnvVars(value);
            }
            return result;
        }

        return obj;
    }

    /**
     * Merge file config with environment variables
     * Environment variables have higher priority
     */
    private mergeWithEnv(fileConfig: Partial<AppConfig>): Partial<AppConfig> {
        const env = process.env;

        return {
            server: {
                port: env.PORT
                    ? parseInt(env.PORT, 10)
                    : (fileConfig.server?.port ?? 3000),
                host: env.HOST ?? fileConfig.server?.host ?? '0.0.0.0',
                publicUrl: env.PUBLIC_URL ?? fileConfig.server?.publicUrl,
                cors: {
                    enabled:
                        env.CORS_ENABLED === 'false'
                            ? false
                            : (fileConfig.server?.cors?.enabled ?? true),
                    origins: env.CORS_ORIGIN?.split(',') ??
                        fileConfig.server?.cors?.origins ?? ['*'],
                    credentials: fileConfig.server?.cors?.credentials ?? true,
                },
                rateLimit: {
                    enabled:
                        env.RATE_LIMIT_ENABLED === 'false'
                            ? false
                            : (fileConfig.server?.rateLimit?.enabled ?? true),
                    max: env.RATE_LIMIT_MAX
                        ? parseInt(env.RATE_LIMIT_MAX, 10)
                        : (fileConfig.server?.rateLimit?.max ?? 100),
                    timeWindow:
                        fileConfig.server?.rateLimit?.timeWindow ?? '1m',
                },
            },
            database: {
                url: env.DATABASE_URL ?? fileConfig.database?.url ?? '',
                pool: fileConfig.database?.pool,
                ssl:
                    env.DATABASE_SSL === 'true'
                        ? true
                        : (fileConfig.database?.ssl ?? false),
            },
            redis: {
                url: env.REDIS_URL ?? fileConfig.redis?.url ?? '',
            },
            security: {
                masterEncryptionKey:
                    env.MASTER_ENCRYPTION_KEY ??
                    fileConfig.security?.masterEncryptionKey ??
                    '',
                jwt: {
                    issuer:
                        env.JWT_ISSUER ??
                        fileConfig.security?.jwt?.issuer ??
                        'ais-forge',
                    audience:
                        env.JWT_AUDIENCE ??
                        fileConfig.security?.jwt?.audience ??
                        'api',
                    accessTokenTTL:
                        env.ACCESS_TOKEN_TTL ??
                        fileConfig.security?.jwt?.accessTokenTTL ??
                        '15m',
                },
                refreshToken: {
                    ttlDays: env.REFRESH_TOKEN_TTL_DAYS
                        ? parseInt(env.REFRESH_TOKEN_TTL_DAYS, 10)
                        : (fileConfig.security?.refreshToken?.ttlDays ?? 30),
                },
                defaultAlgorithm:
                    (env.DEFAULT_SIGNING_ALGORITHM as (typeof signingAlgorithm)[number]) ??
                    fileConfig.security?.defaultAlgorithm ??
                    'ES256',
            },
            keyRotation: {
                enabled:
                    env.KEY_ROTATION_ENABLED === 'false'
                        ? false
                        : (fileConfig.keyRotation?.enabled ?? true),
                schedule:
                    env.KEY_ROTATION_SCHEDULE ??
                    fileConfig.keyRotation?.schedule ??
                    '0 2 * * *',
                thresholdDays: env.KEY_ROTATION_THRESHOLD
                    ? parseInt(env.KEY_ROTATION_THRESHOLD, 10)
                    : (fileConfig.keyRotation?.thresholdDays ?? 30),
                autoPurge:
                    env.KEY_AUTO_PURGE === 'false'
                        ? false
                        : (fileConfig.keyRotation?.autoPurge ?? true),
                alerting: {
                    enabled: fileConfig.keyRotation?.alerting?.enabled ?? true,
                    expirationThresholdDays:
                        fileConfig.keyRotation?.alerting
                            ?.expirationThresholdDays ?? 14,
                },
            },
            logging: {
                level:
                    (env.LOG_LEVEL as
                        | 'error'
                        | 'trace'
                        | 'debug'
                        | 'info'
                        | 'warn'
                        | 'fatal') ??
                    fileConfig.logging?.level ??
                    'info',
                format:
                    (env.LOG_FORMAT as 'json' | 'pretty') ??
                    fileConfig.logging?.format ??
                    'json',
                redactSensitive: fileConfig.logging?.redactSensitive ?? true,
            },
            alerting: {
                slack: {
                    enabled:
                        env.SLACK_ENABLED === 'true' ||
                        fileConfig.alerting?.slack?.enabled ||
                        false,
                    webhookUrl:
                        env.SLACK_WEBHOOK_URL ??
                        fileConfig.alerting?.slack?.webhookUrl,
                    channel:
                        env.SLACK_CHANNEL ??
                        fileConfig.alerting?.slack?.channel,
                },
                email: {
                    enabled:
                        env.EMAIL_ALERTS_ENABLED === 'true' ||
                        fileConfig.alerting?.email?.enabled ||
                        false,
                    smtp: {
                        host:
                            env.SMTP_HOST ??
                            fileConfig.alerting?.email?.smtp?.host,
                        port: env.SMTP_PORT
                            ? parseInt(env.SMTP_PORT, 10)
                            : fileConfig.alerting?.email?.smtp?.port,
                        secure:
                            env.SMTP_SECURE === 'false'
                                ? false
                                : (fileConfig.alerting?.email?.smtp?.secure ??
                                  true),
                        auth: {
                            user:
                                env.SMTP_USER ??
                                fileConfig.alerting?.email?.smtp?.auth?.user,
                            pass:
                                env.SMTP_PASS ??
                                fileConfig.alerting?.email?.smtp?.auth?.pass,
                        },
                    },
                    from: env.EMAIL_FROM ?? fileConfig.alerting?.email?.from,
                    to:
                        env.EMAIL_TO?.split(',') ??
                        fileConfig.alerting?.email?.to,
                },
                pagerduty: {
                    enabled:
                        env.PAGERDUTY_ENABLED === 'true' ||
                        fileConfig.alerting?.pagerduty?.enabled ||
                        false,
                    integrationKey:
                        env.PAGERDUTY_INTEGRATION_KEY ??
                        fileConfig.alerting?.pagerduty?.integrationKey,
                },
            },
            features: {
                introspection:
                    env.ENABLE_INTROSPECTION === 'false'
                        ? false
                        : (fileConfig.features?.introspection ?? true),
                openidConfig:
                    env.ENABLE_OPENID_CONFIG === 'false'
                        ? false
                        : (fileConfig.features?.openidConfig ?? true),
                adminApi:
                    env.ENABLE_ADMIN_API === 'false'
                        ? false
                        : (fileConfig.features?.adminApi ?? true),
                multiAlgorithm: fileConfig.features?.multiAlgorithm ?? false,
            },
            metrics: {
                enabled:
                    env.METRICS_ENABLED === 'true' ||
                    fileConfig.metrics?.enabled ||
                    false,
                port: env.METRICS_PORT
                    ? parseInt(env.METRICS_PORT, 10)
                    : (fileConfig.metrics?.port ?? 9090),
                path:
                    env.METRICS_PATH ?? fileConfig.metrics?.path ?? '/metrics',
                prometheus: fileConfig.metrics?.prometheus ?? true,
            },
            isProduction:
                env.NODE_ENV === 'production' ||
                fileConfig.isProduction ||
                false,
        };
    }
    /**
     * Get current configuration
     */
    get(): AppConfig {
        if (!this.config) {
            throw new Error('Configuration not loaded. Call load() first.');
        }
        return this.config;
    }

    /**
     * Reload configuration
     */
    reload(): AppConfig {
        this.config = null;
        return this.load();
    }
}

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

export const configLoader = new ConfigLoader();

// Helper to get config
export function getConfig(): AppConfig {
    return configLoader.get();
}

// ============================================================================
// CONFIGURATION EXPORT FOR SPECIFIC MODULES
// ============================================================================

export function getServerConfig() {
    return getConfig().server;
}

export function getDatabaseConfig() {
    return getConfig().database;
}

export function getSecurityConfig() {
    return getConfig().security;
}

export function getKeyRotationConfig() {
    return getConfig().keyRotation;
}

export function getAlertingConfig() {
    return getConfig().alerting;
}

export function getMetricsConfig() {
    return getConfig().metrics;
}
