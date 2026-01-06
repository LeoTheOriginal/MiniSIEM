import re
import json
from datetime import datetime


class LogCollector:
    """
    Pobiera i normalizuje logi z różnych systemów (Linux/Windows).
    """

    LINUX_PATTERNS = {
        'failed_password': re.compile(r"Failed password for (?:invalid user )?([\w.-]+) from ([\d.]+)"),
        'invalid_user': re.compile(r"Invalid user ([\w.-]+) from ([\d.]+)"),
        'sudo': re.compile(r"sudo:\s+([a-zA-Z0-9._-]+)\s*:"),
    }

    @staticmethod
    def get_linux_logs(ssh_client, last_fetch_time=None, sudo_password=None):
        logs = []

        if sudo_password:
            cmd = "sudo -S journalctl -u ssh -o json --no-pager"
        else:
            cmd = "sudo journalctl -u ssh -o json --no-pager"

        if last_fetch_time:
            # Używamy formatu bez spacji (T zamiast spacji)
            since_str = last_fetch_time.strftime("%Y-%m-%dT%H:%M:%S")
            cmd += f" --since {since_str}"
        else:
            # -7d to 7 dni temu, format bez spacji, nie wymaga cudzysłowów
            cmd += ' --since -7d'

        print(f"DEBUG [Linux]: Executing command with sudo password: {'YES' if sudo_password else 'NO'}")
        print(f"DEBUG [Linux]: Command: {cmd[:80]}...")

        try:
            stdout, stderr = ssh_client.run(cmd, sudo_password=sudo_password)

            print(f"🔍 SSH STDOUT length: {len(stdout) if stdout else 0}")
            print(f"🔍 SSH STDERR length: {len(stderr) if stderr else 0}")

            if not stdout:
                print("⚠️ STDOUT is empty!")
                if stderr:
                    print(f"⚠️ STDERR: {stderr[:300]}")
                return []

            # print(f"📝 First 300 chars of stdout:\n{stdout[:300]}")

            lines_processed = 0
            messages_checked = 0

            for line in stdout.splitlines():
                if not line.strip():
                    continue
                lines_processed += 1
                try:
                    entry = json.loads(line)
                    message = entry.get('MESSAGE', '')

                    if not message:
                        continue

                    messages_checked += 1

                    # DEBUG: Pokaż pierwsze 10 messages
                    # if messages_checked <= 10:
                    #     print(f"🔍 MESSAGE #{messages_checked}: {message[:200]}")

                    ts_micro = int(entry.get('__REALTIME_TIMESTAMP', 0))
                    timestamp = datetime.fromtimestamp(ts_micro / 1_000_000)

                    parsed = LogCollector._parse_linux_message(message, timestamp)
                    if parsed:
                        print(f"✅ MATCH! {parsed['alert_type']} from {parsed['source_ip']} user={parsed['user']}")
                        logs.append(parsed)

                except json.JSONDecodeError:
                    continue

            print(
                f"📊 Processed {lines_processed} lines, checked {messages_checked} messages, found {len(logs)} threats")

        except Exception as e:
            print(f"Error collecting Linux logs: {e}")
            # import traceback
            # traceback.print_exc()
            return []

        return logs

    @staticmethod
    def _parse_linux_message(message, timestamp):
        match = LogCollector.LINUX_PATTERNS['failed_password'].search(message)
        if match:
            return {
                'timestamp': timestamp,
                'alert_type': 'FAILED_LOGIN',
                'source_ip': match.group(2),
                'user': match.group(1),
                'message': message,
                'raw_log': message
            }

        match = LogCollector.LINUX_PATTERNS['invalid_user'].search(message)
        if match:
            return {
                'timestamp': timestamp,
                'alert_type': 'INVALID_USER',
                'source_ip': match.group(2),
                'user': match.group(1),
                'message': message,
                'raw_log': message
            }

        match = LogCollector.LINUX_PATTERNS['sudo'].search(message)
        if match:
            return {
                'timestamp': timestamp,
                'alert_type': 'SUDO_USAGE',
                'source_ip': 'LOCAL',
                'user': match.group(1),
                'message': message,
                'raw_log': message
            }
        return None

    @staticmethod
    def get_windows_logs(win_client, last_fetch_time=None):
        logs = []

        # --- FIX: Zmiana formatu daty z 'mm' (minuty) na 'MM' (miesiące) ---
        ps_cmd = (
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 -ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "   $xml = [xml]$_.ToXml(); "
            "   $data = @{}; "
            "   $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }; "
            "   [PSCustomObject]@{ "
            "       Timestamp = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "  
            "       IpAddress = $data['IpAddress']; "
            "       TargetUserName = $data['TargetUserName']; "
            "       EventId = $_.Id "
            "   } "
            "} | ConvertTo-Json -Compress"
        )

        print(f"DEBUG [Windows]: Executing PS XML extraction...")

        try:
            stdout = win_client.run_ps(ps_cmd)

            print(f"🔍 Windows PS STDOUT length: {len(stdout) if stdout else 0}")

            if stdout:
                print(f"📝 First 500 chars of Windows stdout:\n{stdout[:500]}")

            if not stdout:
                print("⚠️ Windows PS returned empty output")
                return []

            try:
                # Jeśli PowerShell zwrócił jeden obiekt, może nie być w liście
                if stdout.strip().startswith('{'):
                    stdout = f"[{stdout}]"
                data = json.loads(stdout)
            except json.JSONDecodeError:
                print("WinLog Error: Invalid JSON from PowerShell")
                return []

            entries = [data] if isinstance(data, dict) else data

            for entry in entries:
                ip = entry.get('IpAddress', '-')
                user = entry.get('TargetUserName', 'UNKNOWN')
                ts_str = entry.get('Timestamp')

                try:
                    # Teraz parsowanie zadziała, bo data będzie miała sensowny miesiąc
                    timestamp = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    print(f"⚠️ Błąd parsowania daty z Windows: {ts_str}. Używam teraz().")
                    timestamp = datetime.now()

                if not ip or ip == '-':
                    ip = 'LOCAL_CONSOLE'

                logs.append({
                    'timestamp': timestamp,
                    'alert_type': 'WIN_FAILED_LOGIN',
                    'source_ip': ip,
                    'user': user,
                    'message': f"Windows Logon Failure for user: {user} (Event 4625)",
                    'raw_log': json.dumps(entry)
                })

        except Exception as e:
            print(f"Error collecting Windows logs: {e}")
            return []

        return logs