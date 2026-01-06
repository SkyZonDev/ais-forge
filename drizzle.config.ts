import { config } from 'dotenv';
import { defineConfig } from 'drizzle-kit';

config();

export default defineConfig({
    out: './drizzle',
    schema: './src/db',
    dialect: 'postgresql',
    dbCredentials: {
        url:
            process.env.DRIZZLE_ENV === 'test'
                ? process.env.DATABASE_TEST_URL!
                : process.env.DATABASE_URL!,
    },
    verbose: true,
    strict: true,
});
