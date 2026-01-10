import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { config } from '../../config';
import * as schema from '../../db/schema';

const pool = new Pool({
    connectionString: config.db.pgUrl,
    max: 10,
    min: 2,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    keepAlive: true,
    keepAliveInitialDelayMillis: 10000,
    allowExitOnIdle: false,
    log: console.log,
});

pool.on('error', (err) => {
    console.error('Unexpected database error:', err);
    // Ne pas crasher le pod, juste logger
});

pool.on('connect', () => {
    console.log('New database connection established');
});

const db = drizzle(pool, {
    schema,
    logger: process.env.NODE_ENV === 'development',
});

async function checkDatabaseHealth(): Promise<boolean> {
    try {
        await pool.query('SELECT 1');
        return true;
    } catch (error) {
        console.error('Database health check failed:', error);
        return false;
    }
}

async function closeDatabaseConnection(): Promise<void> {
    console.log('Closing database connections...');
    await pool.end();
    console.log('Database connections closed');
}

export { db, pool, checkDatabaseHealth, closeDatabaseConnection };
