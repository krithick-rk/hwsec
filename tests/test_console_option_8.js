import assert from 'assert';
import path from 'path';
import fs from 'fs';
import { ConsoleApp } from '../src/core/console/consoleApp.js';

console.log("=== Running Console Menu Option 8 Regression Test ===");

const testOutputDir = path.resolve('hwsec-output/test-console-opt8');

if (fs.existsSync(testOutputDir)) {
    fs.rmSync(testOutputDir, { recursive: true, force: true });
}

const app = new ConsoleApp({
    outputDir: testOutputDir,
    skipOnboarding: true
});

let outputLog = '';
const originalLog = console.log;
console.log = (...args) => {
    outputLog += args.join(' ') + '\n';
};

let promptLog = [];
app.ask = async (q) => {
    promptLog.push(q);
    if (q.includes('Select option')) {
        // Return 8 the first time, then 0 to exit setup
        return promptLog.length === 1 ? '8' : '0';
    }
    if (q.includes('Press ENTER')) {
        return '';
    }
    return '';
};

try {
    app.running = true;
    await app.runSessionSetupMenu();
} finally {
    console.log = originalLog;
}

assert(outputLog.includes('[+] Checking tool capabilities...'), "Option 8 must indicate checking tool capabilities");
assert(outputLog.includes('HWSEC TOOLCHAIN STATUS'), "Option 8 must display the live tool status");

// Verify that it asks to press ENTER and then returns to the setup menu by asking for an option again
assert(promptLog.length >= 3, "Must prompt for option, then ENTER, then option again");
assert(promptLog[1].includes('Press ENTER to return to setup menu...'), "Must ask operator to press ENTER before returning to menu");
assert(promptLog[2].includes('Select option'), "Must return to the parent menu after tool status");

app.close();

try {
    if (fs.existsSync(testOutputDir)) {
        fs.rmSync(testOutputDir, { recursive: true, force: true });
    }
} catch {}

console.log("\n>>> OPTION 8 MENU-TO-HANDLER TEST PASSED! <<<\n");
