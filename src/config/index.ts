import 'dotenv/config';
import { configLoader } from './loader';

export const config = configLoader.load();
