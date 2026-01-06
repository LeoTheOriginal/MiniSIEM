import time
from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required
from datetime import timezone, datetime, timedelta
import os
from sqlalchemy import func

from app.models import Host, LogSource, LogArchive, Alert, IPRegistry
from app.services.remote_client import RemoteClient
from app.services.win_client import WinClient
from app.services.log_collector import LogCollector
from app.services.data_manager import DataManager
from app.services.log_analyzer import LogAnalyzer
from app.extensions import db

api_bp = Blueprint("api_hosts", __name__)


# --- CRUD HOSTS (ZABEZPIECZONE) ---

@api_bp.route("/hosts", methods=["GET"])
def get_hosts():
    hosts = Host.query.all()
    return jsonify([h.to_dict() for h in hosts])


@api_bp.route("/hosts", methods=["POST"])
@login_required
def add_host():
    data = request.get_json()
    if not data: return jsonify({"error": "Brak danych"}), 400
    if Host.query.filter_by(ip_address=data.get("ip_address")).first():
        return jsonify({"error": "IP musi być unikalne"}), 409
    new_host = Host(hostname=data.get("hostname"), ip_address=data.get("ip_address"), os_type=data.get("os_type"))
    db.session.add(new_host)
    db.session.commit()
    return jsonify(new_host.to_dict()), 201


@api_bp.route("/hosts/<int:host_id>", methods=["DELETE"])
@login_required
def delete_host(host_id):
    host = Host.query.get_or_404(host_id)
    db.session.delete(host)
    db.session.commit()
    return jsonify({"message": "Usunięto hosta"}), 200


@api_bp.route("/hosts/<int:host_id>", methods=["PUT"])
@login_required
def update_host(host_id):
    host = Host.query.get_or_404(host_id)
    data = request.get_json()
    if 'hostname' in data: host.hostname = data['hostname']
    if 'ip_address' in data: host.ip_address = data['ip_address']
    if 'os_type' in data: host.os_type = data['os_type']
    db.session.commit()
    return jsonify(host.to_dict()), 200


# --- MONITORING LIVE (GOTOWE) ---

@api_bp.route("/hosts/<int:host_id>/ssh-info", methods=["GET"])
def get_ssh_info(host_id):
    host = Host.query.get_or_404(host_id)
    ssh_user = current_app.config.get("SSH_DEFAULT_USER", "vagrant")
    ssh_port = current_app.config.get("SSH_DEFAULT_PORT", 22)
    ssh_key = current_app.config.get("SSH_KEY_FILE")
    ssh_password = current_app.config.get("SSH_PASSWORD")

    try:
        # Wybór metody autoryzacji
        auth_params = {}
        if ssh_password:
            auth_params['password'] = ssh_password
        elif ssh_key:
            auth_params['key_file'] = ssh_key

        with RemoteClient(host=host.ip_address, user=ssh_user, port=ssh_port, **auth_params) as remote:
            ram_out, _ = remote.run("free -m | grep Mem | awk '{print $7}'")
            disk_percentage, _ = remote.run("df -h | grep '/$' | awk '{print $5}'")
            if not disk_percentage: disk_percentage, _ = remote.run("df -h | grep '/dev/sda1' | awk '{print $5}'")
            disk_total, _ = remote.run("df -h | grep '/dev/sda1' | awk '{print $2}'")
            cpu_load, _ = remote.run("uptime | awk -F'load average:' '{ print $2 }' | cut -d',' -f1")
            uptime_seconds_str, _ = remote.run("cat /proc/uptime | awk '{print $1}'")
            uptime_formatted = "N/A"
            try:
                total_seconds = float(uptime_seconds_str)
                hours = int(total_seconds // 3600)
                minutes = int((total_seconds % 3600) // 60)
                uptime_formatted = f"{hours}h {minutes}m"
            except:
                pass

            return jsonify({
                "free_ram_mb": ram_out.strip(), "disk_info": disk_percentage.strip(),
                "disk_total": disk_total.strip(), "cpu_load": cpu_load.strip(), "uptime_hours": uptime_formatted
            }), 200
    except Exception as e:
        return jsonify({"error": f"Błąd połączenia: {str(e)}"}), 500


@api_bp.route("/hosts/<int:host_id>/windows-info", methods=["GET"])
def get_windows_info(host_id):
    import psutil
    host = Host.query.get_or_404(host_id)
    if host.os_type != "WINDOWS": return jsonify({"error": "Wrong OS"}), 400
    try:
        mem = psutil.virtual_memory()
        free_ram_mb = str(round(mem.available / (1024 * 1024)))
        cpu_load = f"{psutil.cpu_percent(interval=0.1)}%"
        try:
            usage = psutil.disk_usage("C:\\")
            disk_percentage = f"{usage.percent}%"
            disk_total = f"{round(usage.total / (1024 ** 3), 1)}GB"
        except:
            disk_percentage, disk_total = "N/A", "?"
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_seconds = (datetime.now() - boot_time).total_seconds()
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        return jsonify({
            "free_ram_mb": free_ram_mb, "disk_info": disk_percentage,
            "disk_total": disk_total, "cpu_load": cpu_load, "uptime_hours": f"{hours}h {minutes}m"
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ===================================================================
# ETAP 2: POBIERANIE LOGÓW (ZAIMPLEMENTOWANE)
# ===================================================================

@api_bp.route("/hosts/<int:host_id>/logs", methods=["POST"])
def fetch_logs(host_id):
    host = Host.query.get_or_404(host_id)

    print(f"📥 [FETCH_LOGS] Start dla hosta: {host.hostname} ({host.ip_address})")

    # 1. Zarządzanie stanem (LogSource)
    log_source = LogSource.query.filter_by(host_id=host.id).first()
    if not log_source:
        log_source = LogSource(host_id=host.id, log_type='security', last_fetch=None)
        db.session.add(log_source)
        db.session.commit()
        print(f"🆕 Utworzono nowy LogSource dla hosta #{host.id}")
    else:
        print(f"✅ LogSource istnieje, last_fetch: {log_source.last_fetch}")

    try:
        logs = []

        # 2. Pobieranie logów w zależności od OS
        if host.os_type == "LINUX":
            ssh_user = current_app.config.get("SSH_DEFAULT_USER", "vagrant")
            ssh_port = current_app.config.get("SSH_DEFAULT_PORT", 22)
            ssh_key = current_app.config.get("SSH_KEY_FILE")
            ssh_password = current_app.config.get("SSH_PASSWORD")

            # Wybór metody autoryzacji
            auth_params = {}
            if ssh_password:
                auth_params['password'] = ssh_password
            elif ssh_key:
                auth_params['key_file'] = ssh_key

            with RemoteClient(host=host.ip_address, user=ssh_user, port=ssh_port, **auth_params) as client:
                # PRZEKAZUJEMY ssh_password jako sudo_password!
                logs = LogCollector.get_linux_logs(
                    client,
                    last_fetch_time=log_source.last_fetch,
                    sudo_password=ssh_password  # ← KLUCZOWA ZMIANA!
                )

        elif host.os_type == "WINDOWS":
            with WinClient() as client:
                logs = LogCollector.get_windows_logs(client, last_fetch_time=log_source.last_fetch)
        else:
            return jsonify({"error": "Nieobsługiwany typ systemu"}), 400

        print(f"📊 Pobrano {len(logs)} wpisów z logów")

        # 3. Jeśli brak logów
        if not logs:
            print("⚠️ Brak nowych logów do analizy")
            return jsonify({
                "message": "Brak nowych logów do analizy",
                "logs_collected": 0,
                "alerts_generated": 0
            }), 200

        # 4. Zapis do Parquet (Forensics)
        print(f"💾 Zapisuję {len(logs)} logów do Parquet...")
        filename, record_count = DataManager.save_logs_to_parquet(logs, host.id)

        if not filename:
            print("❌ Błąd zapisu logów do Parquet!")
            return jsonify({"error": "Błąd zapisu logów"}), 500

        print(f"✅ Zapisano do: {filename} ({record_count} rekordów)")

        # 5. Aktualizacja LogSource (last_fetch)
        log_source.last_fetch = datetime.now(timezone.utc)
        db.session.commit()
        print(f"🔄 Zaktualizowano last_fetch: {log_source.last_fetch}")

        # 6. Rejestracja w LogArchive
        archive = LogArchive(
            host_id=host.id,
            filename=filename,
            record_count=record_count,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(archive)
        db.session.commit()
        print(f"📚 Dodano wpis do LogArchive")

        # 7. Analiza zagrożeń (SIEM) - Teraz z Cross-Host Correlation!
        print(f"🔍 Wywołuję LogAnalyzer.analyze_parquet('{filename}', {host.id})...")
        alerts_count = LogAnalyzer.analyze_parquet(filename, host.id)
        print(f"✅ Analiza zakończona, wygenerowano {alerts_count} alertów")

        return jsonify({
            "message": "Logi pobrane i przeanalizowane",
            "logs_collected": record_count,
            "alerts_generated": alerts_count,
            "filename": filename
        }), 200

    except Exception as e:
        print(f"❌ BŁĄD w fetch_logs: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Błąd pobierania logów: {str(e)}"}), 500


# ===================================================================
# ETAP 3: API DLA REJESTRU IP I ALERTÓW (ZAIMPLEMENTOWANE)
# ===================================================================

@api_bp.route("/ips", methods=["GET"])
def get_ips():
    ips = IPRegistry.query.order_by(IPRegistry.last_seen.desc()).all()
    return jsonify([{
        'id': ip.id,
        'ip_address': ip.ip_address,
        'status': ip.status,
        'last_seen': ip.last_seen.strftime('%Y-%m-%d %H:%M:%S') if ip.last_seen else '-'
    } for ip in ips])


@api_bp.route("/ips", methods=["POST"])
@login_required
def add_ip():
    data = request.get_json()
    if not data or 'ip_address' not in data:
        return jsonify({"error": "Brak adresu IP"}), 400

    if IPRegistry.query.filter_by(ip_address=data['ip_address']).first():
        return jsonify({"error": "IP już istnieje"}), 409

    new_ip = IPRegistry(
        ip_address=data['ip_address'],
        status=data.get('status', 'UNKNOWN')
    )
    db.session.add(new_ip)
    db.session.commit()
    return jsonify({"message": "IP dodany"}), 201


@api_bp.route("/ips/<int:ip_id>", methods=["PUT"])
@login_required
def update_ip(ip_id):
    ip = IPRegistry.query.get_or_404(ip_id)
    data = request.get_json()
    if 'status' in data: ip.status = data['status']
    if 'ip_address' in data: ip.ip_address = data['ip_address']
    db.session.commit()
    return jsonify({"message": "Zaktualizowano"}), 200


@api_bp.route("/ips/<int:ip_id>", methods=["DELETE"])
@login_required
def delete_ip(ip_id):
    ip = IPRegistry.query.get_or_404(ip_id)
    db.session.delete(ip)
    db.session.commit()
    return jsonify({"message": "Usunięto"}), 200


@api_bp.route("/alerts", methods=["GET"])
def get_recent_alerts():
    # Pobierz parametry z URL
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    # Zabezpieczenie - max 100 per strona
    per_page = min(per_page, 100)

    # Paginacja przez SQLAlchemy
    pagination = Alert.query.order_by(Alert.timestamp.desc()).paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    return jsonify({
        'alerts': [alert.to_dict() for alert in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'pages': pagination.pages,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev
    })

# ===================================================================
# ⭐ ZADANIE DODATKOWE: Endpoint dla statystyk (Chart.js)
# ===================================================================

@api_bp.route("/alerts/stats", methods=["GET"])
def get_alert_stats():
    """
    Zwraca statystyki alertów dla wykresu:
    - Liczba alertów na godzinę (ostatnie 24h)
    - Top 5 atakujących IP
    """
    now = datetime.now(timezone.utc)
    twenty_four_hours_ago = now - timedelta(hours=24)

    # 1. Alerty na godzinę (ostatnie 24h)
    hourly_alerts = db.session.query(
        func.strftime('%H:00', Alert.timestamp).label('hour'),
        func.count(Alert.id).label('count')
    ).filter(
        Alert.timestamp >= twenty_four_hours_ago
    ).group_by('hour').order_by('hour').all()

    # Wypełnij brakujące godziny zerami
    hours_dict = {f"{h:02d}:00": 0 for h in range(24)}
    for hour, count in hourly_alerts:
        if hour:
            hours_dict[hour] = count

    hourly_data = {
        'labels': list(hours_dict.keys()),
        'data': list(hours_dict.values())
    }

    # 2. Top 5 atakujących IP
    top_ips = db.session.query(
        Alert.source_ip,
        func.count(Alert.id).label('count')
    ).filter(
        Alert.source_ip.isnot(None),
        Alert.source_ip != 'LOCAL',
        Alert.source_ip != 'LOCAL_CONSOLE'
    ).group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(5).all()

    top_ips_data = {
        'labels': [ip for ip, count in top_ips],
        'data': [count for ip, count in top_ips]
    }

    # 3. Severity distribution
    severity_stats = db.session.query(
        Alert.severity,
        func.count(Alert.id).label('count')
    ).group_by(Alert.severity).all()

    severity_data = {
        'labels': [sev for sev, count in severity_stats],
        'data': [count for sev, count in severity_stats]
    }

    return jsonify({
        'hourly': hourly_data,
        'top_ips': top_ips_data,
        'severity': severity_data
    })