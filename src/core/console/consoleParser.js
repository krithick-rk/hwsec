/**
 * Console Command Parser
 * 
 * Tokenizes and parses user input for the HWSEC Interactive Security Operations Console.
 * Supports quoted arguments, flags, strict validation, and sensitive token redaction.
 */

export class ConsoleParser {
    /**
     * Tokenizes a command string into arguments, respecting single and double quotes.
     * @param {string} input 
     * @returns {Array<string>}
     */
    static tokenize(input) {
        if (!input || typeof input !== 'string') return [];
        const trimmed = input.trim();
        if (!trimmed) return [];

        const tokens = [];
        let current = '';
        let inSingle = false;
        let inDouble = false;
        let escaped = false;

        for (let i = 0; i < trimmed.length; i++) {
            const char = trimmed[i];

            if (escaped) {
                if (char === '"' || char === "'" || char === '\\') {
                    current += char;
                } else {
                    current += '\\' + char;
                }
                escaped = false;
                continue;
            }

            if (char === '\\') {
                escaped = true;
                continue;
            }

            if (char === "'" && !inDouble) {
                inSingle = !inSingle;
                continue;
            }

            if (char === '"' && !inSingle) {
                inDouble = !inDouble;
                continue;
            }

            if (/\s/.test(char) && !inSingle && !inDouble) {
                if (current.length > 0) {
                    tokens.push(current);
                    current = '';
                }
                continue;
            }

            current += char;
        }

        if (escaped) {
            current += '\\';
        }

        if (current.length > 0) {
            tokens.push(current);
        }

        return tokens;
    }

    /**
     * Parses a tokenized command line into a structured command object.
     * @param {string} input 
     * @returns {{ command: string, subcommand: string|null, args: Array<string>, raw: string }}
     */
    static parse(input) {
        const tokens = this.tokenize(input);
        if (tokens.length === 0) {
            return { command: '', subcommand: null, args: [], raw: input };
        }

        const cmd = tokens[0].toLowerCase();
        let subcommand = null;
        let args = tokens.slice(1);

        // Multi-word command aliases: "show options" -> command: "show", subcommand: "options"
        if (cmd === 'show' && args.length > 0) {
            subcommand = args[0].toLowerCase();
            args = args.slice(1);
        } else if (['inspect', 'doctor', 'pov', 'sessions', 'providers'].includes(cmd) && args.length > 0) {
            subcommand = args[0].toLowerCase();
            args = args.slice(1);
        }

        return {
            command: cmd,
            subcommand,
            args,
            raw: input.trim()
        };
    }

    /**
     * Sanitizes command strings to prevent API tokens or secrets from leaking into logs/history.
     * @param {string} input 
     * @returns {string}
     */
    static redactSensitive(input) {
        if (!input) return '';
        // Redact values after api_key, token, secret, password, or rotate/set key values
        let s = input.replace(/(key|token|secret|password)\s+([^\s]+)/gi, '$1 ********');
        s = s.replace(/(providers\s+(rotate|set|add)\s+[^\s]+\s+)([^\s]+)/gi, '$1********');
        return s;
    }
}
