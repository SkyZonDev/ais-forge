import 'dotenv/config';
import { version } from '../../package.json';

export const config = {
    port: Number(process.env.PORT) || 3000,
    host: process.env.HOST || 'localhost',
    app_name: process.env.APPNAME || 'dev',
    environment: process.env.NODE_ENV || 'development',
    isProduction: process.env.NODE_ENV === 'production',
    isTest: process.env.NODE_ENV === 'test',
    version,
    trusted_origins: [
        ...(process.env.TRUSTED_ORIGINS
            ? process.env.TRUSTED_ORIGINS.split(',').map((origin) =>
                  origin.trim()
              )
            : []),
        ...(process.env.VERCEL_URL ? [process.env.VERCEL_URL] : []),
    ],
};
