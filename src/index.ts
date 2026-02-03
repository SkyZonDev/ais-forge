import { buildApp } from './app';
import { config } from './config';
import { closeDatabaseConnection } from './utils/db';

async function main() {
    try {
        const port = config.server.port;
        const host = config.server.host;

        console.log('\n📦 Configuration loaded:');
        console.log(
            `  • Environment: ${process.env.NODE_ENV || 'development'}`
        );
        console.log(`  • Server: ${config.server.host}:${config.server.port}`);
        console.log(`  • Public URL: ${config.server.publicUrl || 'not set'}`);
        console.log(
            `  • Database: ${config.database.url.replace(/:[^:@]+@/, ':****@')}`
        );
        console.log(
            `  • Redis: ${config.redis.url.replace(/:[^:@]+@/, ':****@')}`
        );
        console.log(
            `  • Key rotation: ${config.keyRotation.enabled ? 'enabled' : 'disabled'}`
        );
        console.log(
            `  • Token cleanup: ${config.tokenCleanup.enabled ? 'enabled' : 'disabled'}`
        );
        console.log(
            `  • Metrics: ${config.metrics?.enabled ? 'enabled' : 'disabled'}`
        );
        console.log(
            `  • Alerting: Slack=${config.alerting?.slack?.enabled}, Email=${config.alerting?.email?.enabled}`
        );
        console.log('');

        const app = await buildApp();

        const shutdown = async (signal: string) => {
            app.log.info(`Received ${signal}. Shutting down API...`);
            try {
                await app.close();
                await closeDatabaseConnection();
                app.log.info('Graceful shutdown completed');
                process.exit(0);
            } catch (error) {
                app.log.error('Error during shutdown: ' + error);
                process.exit(1);
            }
        };

        const uncaughtException = async (err: Error) => {
            app.log.fatal(err);
            process.exit(1);
        };

        await app.listen({ port, host });
        console.info(`\n✅ AIS Forge is running!`);
        console.info(
            `   HTTP: http://${config.server.host}:${config.server.port}`
        );
        console.info(
            `   JWKS: ${config.server.publicUrl || 'http://localhost:3000'}/.well-known/jwks.json`
        );
        console.info(
            `   Health: ${config.server.publicUrl || 'http://localhost:3000'}/health`
        );

        if (config.metrics?.enabled) {
            console.info(
                `   Metrics: http://${config.server.host}:${config.metrics.port}${config.metrics.path}`
            );
        }
        console.info('');

        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
        process.on('uncaughtException', uncaughtException);
    } catch (e) {
        console.error('❌ Failed to start application:', e);
        process.exit(1);
    }
}

main();
