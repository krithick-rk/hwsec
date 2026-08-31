import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export class Workspace {
    /**
     * @param {string} baseDir 
     */
    constructor(baseDir) {
        const now = new Date();
        const timestamp = now.toISOString().replace(/[-:T]/g, '').slice(0, 14);
        const randId = crypto.randomBytes(4).toString('hex');
        this.analysisId = `${timestamp}-${randId}`;
        this.outputDir = path.join(baseDir, this.analysisId);
        
        this._initDirectories();
    }

    _initDirectories() {
        const dirs = [
            'inventory', 'hypotheses', 'tools', 'evidence', 
            'findings', 'verification', 'report', 'logs'
        ];
        
        if (!fs.existsSync(this.outputDir)) {
            fs.mkdirSync(this.outputDir, { recursive: true });
        }
        
        for (const dir of dirs) {
            const fullPath = path.join(this.outputDir, dir);
            if (!fs.existsSync(fullPath)) {
                fs.mkdirSync(fullPath, { recursive: true });
            }
        }
    }

    /**
     * @param {string} name 
     * @param {Object} data 
     */
    saveJson(name, data) {
        const fullPath = path.join(this.outputDir, name);
        fs.writeFileSync(fullPath, JSON.stringify(data, null, 2), 'utf-8');
    }

    /**
     * @param {string} name 
     * @param {string} content 
     */
    saveMarkdown(name, content) {
        const fullPath = path.join(this.outputDir, name);
        fs.writeFileSync(fullPath, content, 'utf-8');
    }
}
