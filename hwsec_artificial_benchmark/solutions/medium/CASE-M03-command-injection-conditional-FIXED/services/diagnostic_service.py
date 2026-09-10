import subprocess
import re

TARGET_PATTERN = re.compile(r'^[a-zA-Z0-9.-]+$')


class DiagnosticService:
    TOOLS = {
        'ping': 'Network connectivity check (ICMP)',
        'traceroute': 'Network path tracing',
        'dns_lookup': 'DNS resolution check',
    }

    def available_tools(self):
        return [{'name': k, 'description': v} for k, v in self.TOOLS.items()]

    def run_tool(self, target, tool):
        if not TARGET_PATTERN.match(target) or len(target) > 255:
            return {'error': 'invalid target format'}

        if tool == 'ping':
            return self._run_ping(target)
        elif tool == 'traceroute':
            return self._run_traceroute(target)
        elif tool == 'dns_lookup':
            return self._run_dns_lookup(target)
        else:
            return {'error': f'unknown tool: {tool}', 'available': list(self.TOOLS.keys())}

    def _run_ping(self, target):
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '2', target],
            capture_output=True, text=True, timeout=10
        )
        return {
            'tool': 'ping',
            'target': target,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }

    def _run_traceroute(self, target):
        result = subprocess.run(
            ['traceroute', '-m', '5', target],
            capture_output=True, text=True, timeout=15
        )
        return {
            'tool': 'traceroute',
            'target': target,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }

    def _run_dns_lookup(self, target):
        result = subprocess.run(
            ['nslookup', target],
            capture_output=True, text=True, timeout=10
        )
        return {
            'tool': 'dns_lookup',
            'target': target,
            'output': result.stdout,
            'error': result.stderr,
            'returncode': result.returncode
        }
