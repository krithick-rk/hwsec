import fs from 'fs';
import path from 'path';

export function loadConfig(configPath) {
    if (fs.existsSync(configPath)) {
        const raw = fs.readFileSync(configPath, 'utf-8');
        try {
            return JSON.parse(raw);
        } catch (e) {
            console.error(`[!] Failed to parse config file ${configPath}:`, e.message);
            return {};
        }
    }
    return {};
}
