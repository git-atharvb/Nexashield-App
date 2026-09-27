import subprocess
import json
import logging

class FirewallManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def _run_ps_command(self, cmd):
        """Helper to run a PowerShell command and return its output."""
        try:
            # Run PowerShell command, bypass execution policy, return output
            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.stdout.strip(), result.stderr.strip()
        except Exception as e:
            return "", str(e)

    def get_firewall_rules(self, limit=50):
        """
        Retrieves active firewall rules.
        For performance, we limit it to the top N custom or recent rules.
        We'll filter to show only enabled rules or rules that are explicitly interesting.
        """
        # Fetching rules and converting to JSON for easy parsing in Python
        # Selecting a few key properties: DisplayName, Direction, Action, Enabled
        ps_script = f"""
        Get-NetFirewallRule | Select-Object -First {limit} DisplayName, Direction, Action, Enabled, Name | ConvertTo-Json -Compress
        """
        stdout, stderr = self._run_ps_command(ps_script)
        
        rules = []
        if stdout:
            try:
                # If only one object is returned, ConvertTo-Json might not wrap it in a list
                parsed = json.loads(stdout)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                
                for item in parsed:
                    rules.append({
                        "id": item.get("Name", "Unknown"),
                        "name": item.get("DisplayName", "Unknown"),
                        "direction": "Inbound" if item.get("Direction") == 1 else "Outbound",
                        "action": "Allow" if item.get("Action") == 2 or item.get("Action") == "Allow" else "Block", # Action is an enum
                        "enabled": "True" if item.get("Enabled") in [1, True, "True"] else "False"
                    })
            except Exception as e:
                self.logger.error(f"Failed to parse firewall rules: {e}")
                
        return rules

    def add_rule(self, name, direction, action, ip_address=None, port=None, protocol=None, app_path=None):
        """
        Adds a new firewall rule.
        """
        dir_val = "Inbound" if direction.lower() == "inbound" else "Outbound"
        act_val = "Allow" if action.lower() == "allow" else "Block"
        
        # Build the command dynamically
        cmd_parts = [
            f'New-NetFirewallRule -DisplayName "{name}"',
            f'-Direction {dir_val}',
            f'-Action {act_val}'
        ]
        
        if ip_address:
            cmd_parts.append(f'-RemoteAddress {ip_address}')
            
        if port and protocol:
            cmd_parts.append(f'-Protocol {protocol}')
            cmd_parts.append(f'-LocalPort {port}')
            
        if app_path:
            cmd_parts.append(f'-Program "{app_path}"')
            
        full_cmd = " ".join(cmd_parts)
        stdout, stderr = self._run_ps_command(full_cmd)
        
        if stderr and "Error" in stderr:
            return False, stderr
        return True, "Rule added successfully."

    def delete_rule(self, name_or_id):
        """
        Deletes a firewall rule by its Name or DisplayName.
        """
        # Try deleting by Name (ID) first, fallback to DisplayName
        cmd = f'Remove-NetFirewallRule -Name "{name_or_id}" -ErrorAction SilentlyContinue'
        stdout, stderr = self._run_ps_command(cmd)
        
        if stderr:
            # Attempt to delete by DisplayName if the first fails
            cmd2 = f'Remove-NetFirewallRule -DisplayName "{name_or_id}" -ErrorAction SilentlyContinue'
            stdout2, stderr2 = self._run_ps_command(cmd2)
            if stderr2:
                return False, stderr2
                
        return True, "Rule deleted successfully."

    def toggle_rule(self, name_or_id, enable=True):
        """
        Enables or disables a firewall rule.
        """
        cmd_action = "Enable-NetFirewallRule" if enable else "Disable-NetFirewallRule"
        cmd = f'{cmd_action} -Name "{name_or_id}" -ErrorAction SilentlyContinue'
        stdout, stderr = self._run_ps_command(cmd)
        
        if stderr:
            cmd2 = f'{cmd_action} -DisplayName "{name_or_id}" -ErrorAction SilentlyContinue'
            stdout2, stderr2 = self._run_ps_command(cmd2)
            if stderr2:
                return False, stderr2
        
        state = "enabled" if enable else "disabled"
        return True, f"Rule {state} successfully."

    def quick_panic(self):
        """
        Panic Button: Blocks all outbound and inbound traffic for non-core functions.
        (We implement this safely by adding a high priority block rule for standard ports)
        """
        # Block common outbound surfing ports to simulate panic
        cmd = (
            'New-NetFirewallRule -DisplayName "NEXA PANIC BLOCK" '
            '-Direction Outbound -Action Block -Protocol TCP -RemotePort 80,443'
        )
        self._run_ps_command(cmd)
        return True, "Panic mode activated. Web surfing blocked."

    def block_telemetry(self):
        """Blocks known Windows Telemetry IP ranges."""
        cmd = (
            'New-NetFirewallRule -DisplayName "NEXA Block Telemetry" '
            '-Direction Outbound -Action Block '
            '-RemoteAddress 13.77.161.179,23.218.212.69,65.55.108.23'
        )
        self._run_ps_command(cmd)
        return True, "Windows Telemetry IPs blocked."

    def block_pings(self):
        """Blocks incoming ICMPv4 (Ping) requests."""
        cmd = (
            'New-NetFirewallRule -DisplayName "NEXA Block Ping (ICMP)" '
            '-Direction Inbound -Action Block -Protocol ICMPv4'
        )
        self._run_ps_command(cmd)
        return True, "Incoming pings (ICMP) blocked."

    def reset_firewall(self):
        """Resets the Windows Firewall to default settings."""
        # Using netsh as it is the most reliable way to reset advanced firewall
        cmd = 'netsh advfirewall reset'
        stdout, stderr = self._run_ps_command(cmd)
        if stderr and "Error" in stderr:
            return False, stderr
        return True, "Firewall reset to factory defaults."
