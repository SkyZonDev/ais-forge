import { randomBytes } from 'crypto';

export function generateMasterKey() {
    const masterKey = randomBytes(32);
    const masterKeyBase64 = masterKey.toString('base64');
    console.log(masterKeyBase64);
    process.exit(0);
}

generateMasterKey();
