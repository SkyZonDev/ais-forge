import { buildApp } from './app';
import { config } from './config';
import { closeDatabaseConnection } from './utils/db';

async function start() {
    const app = await buildApp();
    const port = config.port;
    const host = config.host;

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

    try {
        await app.listen({ port, host });
        app.log.info(`App started at http://${host}:${port}`);
    } catch (e) {
        app.log.error(e);
        process.exit(1);
    }

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    process.on('uncaughtException', uncaughtException);
}

start();
