#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from typing import List, Optional, Tuple

import requests

# --------------------------
# Zabbix config auto-detect
# --------------------------
def get_zabbix_config() -> Tuple[str, str]:
    """
    Checks common locations for Zabbix Agent configs.
    Returns (server_ip, hostname).
    """
    paths_to_check = [
        "/etc/zabbix/zabbix_agent2.conf",
        "/etc/zabbix/zabbix_agentd.conf",
        "/etc/zabbix/zabbix_agent.conf",
    ]

    server = "your_zabbix_server_ip"
    hostname = "your_host_name"
    config_found = False

    for config_path in paths_to_check:
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("ServerActive="):
                            val = line.split("=", 1)[1].strip()
                            # Take first server, strip port if present
                            server = val.split(",")[0].split(";")[0].split(":")[0]
                        elif line.startswith("Hostname="):
                            hostname = line.split("=", 1)[1].strip()
                print(f"Loaded config from {config_path}")
                config_found = True
                break
            except Exception as e:
                print(f"Error reading {config_path}: {e}")

    if not config_found:
        print("No Zabbix config found. Using fallback defaults.")

    return server, hostname


# --------------------------
# Kismet settings
# --------------------------
KISMET_BASE = os.getenv("KISMET_BASE", "http://localhost:2501")
KISMET_USER = os.getenv("KISMET_USER", "admin")
KISMET_PASS = os.getenv("KISMET_PASS", "admin")

# --------------------------
# 4DV / status endpoint (data-age summary)
# --------------------------
FOUR_DV_DATA_AGE_URL = os.getenv(
    "FOUR_DV_DATA_AGE_URL",
    "https://localhost/status/api/v1/data-age",
)
FOUR_DV_TLS_VERIFY = os.getenv("FOUR_DV_TLS_VERIFY", "0").strip().lower() in (
    "1",
    "true",
    "yes",
)
FOUR_DV_FETCH_TIMEOUT = int(os.getenv("FOUR_DV_FETCH_TIMEOUT", "15"))

# --------------------------
# Zabbix defaults
# --------------------------
DEFAULT_ZABBIX_PORT = int(os.getenv("ZABBIX_PORT", "10051"))

STATE_FILENAME = "last_seen_status_state.json"


def script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def state_file_path() -> str:
    return os.path.join(script_dir(), STATE_FILENAME)


def normalize_zabbix_stale_argv() -> None:
    """
    Turn a first argument like '-30m' (Zabbix macro) into '--stale-after', '30m'
    so argparse does not treat it as an unknown flag.
    """
    if len(sys.argv) < 2:
        return
    m = re.fullmatch(r"-(\d+)([smhd]?)", sys.argv[1], re.IGNORECASE)
    if not m:
        return
    unit = (m.group(2) or "m").lower()
    sys.argv[1:2] = ["--stale-after", f"{m.group(1)}{unit}"]


def parse_stale_after(spec: str) -> int:
    """
    Window in seconds for RF OK vs NOTICE. Examples: 30m, 2h, 45s, 1d, 45 (minutes if no suffix).
    Leading '-' is stripped (after normalize_zabbix_stale_argv, usually not needed).
    """
    s = spec.strip().lstrip("-").strip()
    if not s:
        raise ValueError("empty stale-after")
    m = re.fullmatch(r"(\d+)\s*([smhd])?", s, re.IGNORECASE)
    if not m:
        if re.fullmatch(r"\d+", s):
            return int(s) * 60
        raise ValueError(f"invalid stale-after: {spec!r}")
    n = int(m.group(1))
    u = (m.group(2) or "m").lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return n * mult[u]


def load_last_seen_state(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_last_seen_state(
    path: str,
    tpms_unix: Optional[int],
    wifi_unix: Optional[int],
    bt_unix: Optional[int],
) -> None:
    payload = {
        "tpms_last_seen_unix": tpms_unix,
        "wifi_last_seen_unix": wifi_unix,
        "bluetooth_last_seen_unix": bt_unix,
        "written_at": now_str(),
    }
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, path)
    except OSError as e:
        print(f"Warning: could not write state file {path}: {e}")


def merge_rf_freshness(
    base_status: str,
    base_detail: str,
    last_seen_unix: Optional[int],
    stale_after_sec: int,
) -> Tuple[str, str]:
    """
    ERROR: base hardware/service check failed, OR base OK but no sensor reads (no last_seen).
    OK: base OK, we have a last_seen, and it is within stale_after_sec of now.
    NOTICE: base OK, we have a last_seen, but activity is older than stale_after_sec.
    """
    if base_status == "ERROR":
        return base_status, base_detail
    if last_seen_unix is None:
        return (
            "ERROR",
            f"{base_detail}; no sensor reads (no last_seen from Kismet API)",
        )
    now_ts = int(time.time())
    if last_seen_unix > now_ts + 120:
        return "OK", base_detail
    age = now_ts - int(last_seen_unix)
    if age <= stale_after_sec:
        return "OK", base_detail
    return (
        "NOTICE",
        f"{base_detail}; last activity {age}s ago (threshold {stale_after_sec}s)",
    )


# --------------------------
# Utility
# --------------------------
def run_cmd(cmd: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def find_zabbix_agent_binary() -> Optional[str]:
    """Prefer zabbix_agent2; fall back to classic agent (zabbix_agentd / zabbix_agent)."""
    for name in ("zabbix_agent2", "zabbix_agentd", "zabbix_agent"):
        path = shutil.which(name)
        if path:
            return path
    return None


def check_zabbix_agent_ping(timeout: int = 10) -> Tuple[int, str]:
    """
    Run `zabbix_agent2 -t agent.ping` (or classic agent if agent2 is absent).
    Returns (1, detail) when agent.ping reports 1; otherwise (0, detail).
    """
    agent_bin = find_zabbix_agent_binary()
    if not agent_bin:
        return 0, "zabbix_agent2 / zabbix agent binary not found"

    rc, out, err = run_cmd([agent_bin, "-t", "agent.ping"], timeout=timeout)
    combined = "\n".join(x for x in (out, err) if x).strip()
    agent_name = os.path.basename(agent_bin)

    m = re.search(r"agent\.ping\s+\[s\|(\d+)\]", out, re.IGNORECASE)
    if m and m.group(1) == "1":
        return 1, f"{agent_name} agent.ping=1"
    if rc == 0 and re.search(r"agent\.ping.*\|1\]", out, re.IGNORECASE):
        return 1, f"{agent_name} agent.ping OK"

    snippet = combined.replace("\n", " ")[:240] if combined else f"rc={rc}"
    return 0, f"{agent_name} agent.ping failed: {snippet}"


def fetch_4dv_data_age(timeout: int = FOUR_DV_FETCH_TIMEOUT) -> Tuple[Optional[dict], str]:
    """
    GET local 4DV data-age JSON (same source as curl -ks .../data-age).
    TLS verify off by default (FOUR_DV_TLS_VERIFY=1 to enable).
    """
    try:
        import urllib3

        if not FOUR_DV_TLS_VERIFY:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    try:
        resp = requests.get(
            FOUR_DV_DATA_AGE_URL,
            timeout=timeout,
            verify=FOUR_DV_TLS_VERIFY,
        )
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code} from {FOUR_DV_DATA_AGE_URL}"
        return resp.json(), "OK"
    except requests.exceptions.JSONDecodeError as e:
        return None, f"invalid JSON: {e}"
    except requests.exceptions.RequestException as e:
        return None, f"request failed: {e}"


def format_4dv_endpoint_summary(payload: dict) -> str:
    """Plain list of pipeline names: working vs not working."""
    working: List[str] = []
    idle: List[str] = []
    for block in payload.get("results") or []:
        if not isinstance(block, dict):
            continue
        rows = block.get("rows") or []
        if rows:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                name = row.get("table_name") or "?"
                ago = row.get("latest_eventdatetime_human") or "?"
                at = row.get("max_eventdatetime") or "?"
                working.append(f"{name} - {ago} ago ({at})")
        else:
            name = block.get("tableName") or block.get("table_name") or "?"
            idle.append(name)

    lines: List[str] = ["Working pipelines:"]
    lines.extend(working if working else ["(none)"])
    lines.append("")
    lines.append("Not working:")
    lines.extend(idle if idle else ["(none)"])
    return "\n".join(lines)


def build_4dv_endpoint_summary(timeout: int = FOUR_DV_FETCH_TIMEOUT) -> Tuple[str, str]:
    """
    Returns (summary_text, detail) for Zabbix kismet.4dv.endpoint.summary.
    On API failure, summary_text is a short error message.
    """
    payload, detail = fetch_4dv_data_age(timeout=timeout)
    if payload is None:
        return f"4DV data-age API unavailable: {detail}", detail
    try:
        return format_4dv_endpoint_summary(payload), detail
    except (TypeError, ValueError, KeyError) as e:
        return f"4DV data-age parse error: {e}", detail


def send_to_zabbix(zabbix_server: str, zabbix_port: int, host_name: str, key: str, value: str) -> bool:
    cmd = [
        "zabbix_sender",
        "-z", zabbix_server,
        "-p", str(zabbix_port),
        "-s", host_name,
        "-k", key,
        "-o", str(value),
    ]
    try:
        subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Zabbix Sender failed for {key}: {e.output.strip()}")
        return False
    except FileNotFoundError:
        print("ERROR: zabbix_sender not found. Install zabbix-sender.")
        return False


def format_uptime_human(seconds: float) -> str:
    """e.g. '1 day 2 hours 3 minutes' (from /proc/uptime seconds)."""
    s = max(0, int(seconds))
    days, rem = divmod(s, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts: List[str] = []
    if days:
        parts.append(f"{days} day" if days == 1 else f"{days} days")
    if hours or days:
        parts.append(f"{hours} hour" if hours == 1 else f"{hours} hours")
    parts.append(f"{minutes} minute" if minutes == 1 else f"{minutes} minutes")
    return " ".join(parts)


def collect_host_metrics() -> dict:
    """
    Host metrics from /proc (Linux):
    - boot_time: wall-clock when the system was powered on / last booted
    - uptime: human duration since boot (e.g. '1 day 2 hours 3 minutes')
    - mem_available_mb: MemAvailable (fallback MemFree), MB
    - ram_available_mb: MemFree, MB
    """
    m: dict = {
        "boot_time": None,
        "uptime": None,
        "mem_available_mb": None,
        "ram_available_mb": None,
    }
    try:
        with open("/proc/uptime", "r", encoding="utf-8", errors="ignore") as f:
            uptime_sec = float(f.read().split()[0])
        m["uptime"] = format_uptime_human(uptime_sec)
        boot_ts = time.time() - uptime_sec
        m["boot_time"] = datetime.fromtimestamp(boot_ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError, IndexError):
        pass
    try:
        meminfo: dict = {}
        with open("/proc/meminfo", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                parts = v.split()
                if parts:
                    meminfo[k.strip()] = int(parts[0])
        mem_avail_kb = meminfo.get("MemAvailable")
        mem_free_kb = meminfo.get("MemFree")
        if mem_avail_kb is None and mem_free_kb is not None:
            mem_avail_kb = mem_free_kb
        if mem_avail_kb is not None:
            m["mem_available_mb"] = round(mem_avail_kb / 1024.0, 2)
        if mem_free_kb is not None:
            m["ram_available_mb"] = round(mem_free_kb / 1024.0, 2)
    except (OSError, ValueError, TypeError):
        pass
    return m


def send_host_metrics_to_zabbix(
    zabbix_server: str, zabbix_port: int, host_name: str, m: dict
) -> bool:
    """Boot time, human uptime, available memory/RAM — skip keys where value is None."""
    ok = True
    items = [
        ("kismet.system.boot_time", m.get("boot_time")),
        ("kismet.system.uptime", m.get("uptime")),
        ("kismet.system.mem.available_mb", m.get("mem_available_mb")),
        ("kismet.system.ram.available_mb", m.get("ram_available_mb")),
    ]
    for key, val in items:
        if val is None:
            continue
        if not send_to_zabbix(zabbix_server, zabbix_port, host_name, key, str(val)):
            ok = False
    return ok


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def print_debug_report(
    *,
    zabbix_server: str,
    zabbix_port: int,
    host_name: str,
    stale_spec: str,
    stale_after_sec: int,
    state_path: str,
    rssi,
    last_time,
    human_time,
    name,
    band,
    frequency_mhz,
    reason: str,
    fallback_used: bool,
    wifi_last_time,
    wifi_human_time,
    wifi_reason: str,
    wifi_fallback_used: bool,
    bt_last_time,
    bt_human_time,
    bt_reason: str,
    bt_fallback_used: bool,
    wifi_rf_base: str,
    wifi_rf_detail_base: str,
    bt_rf_base: str,
    bt_rf_detail_base: str,
    overall_status: str,
    kismet_active: bool,
    sdr_device_count: int,
    sdr_type: str,
    sdr_present: int,
    rtl_count: int,
    tpms_rf_base: str,
    tpms_rf_detail_base: str,
    tpms_last_unix: Optional[int],
    wifi_last_unix: Optional[int],
    bt_last_unix: Optional[int],
    tpms_rf_status: str,
    tpms_rf_detail_final: str,
    wifi_rf_status: str,
    wifi_rf_detail_final: str,
    bt_rf_status: str,
    bt_rf_detail_final: str,
    remarks: str,
    wifi_last_time_value: str,
    bt_last_time_value: str,
    tpms_rssi_sent: Optional[str],
    tpms_last_time_sent: Optional[str],
    host_metrics: Optional[dict] = None,
    system_online: Optional[int] = None,
    system_online_detail: str = "",
    four_dv_summary: str = "",
    four_dv_summary_detail: str = "",
) -> None:
    print("========== DEBUG ==========")
    print(f"KISMET_BASE={KISMET_BASE!r}")
    print(f"zabbix_server={zabbix_server!r} zabbix_port={zabbix_port} host_name={host_name!r}")
    print(f"stale_spec={stale_spec!r} stale_after_sec={stale_after_sec}")
    print(f"state_file={state_path!r}")
    print("--- TPMS (Kismet API) ---")
    print(f"  reason={reason!r} fallback_used={fallback_used}")
    print(f"  rssi={rssi!r} last_time_unix={last_time!r} human_time={human_time!r}")
    print(f"  name={name!r} band={band!r} frequency_mhz={frequency_mhz!r}")
    print(f"  tpms_last_unix (for freshness)={tpms_last_unix!r}")
    print(f"  tpms_rf_base={tpms_rf_base!r} detail_base={tpms_rf_detail_base!r}")
    print(f"  -> kismet.tpms.rf_status={tpms_rf_status!r} detail={tpms_rf_detail_final!r}")
    print("--- WiFi (Kismet API) ---")
    print(f"  wifi_reason={wifi_reason!r} wifi_fallback_used={wifi_fallback_used}")
    print(f"  wifi_last_time_unix={wifi_last_time!r} wifi_human_time={wifi_human_time!r}")
    print(f"  wifi_last_unix (for freshness)={wifi_last_unix!r}")
    print(f"  wifi_rf_base={wifi_rf_base!r} detail_base={wifi_rf_detail_base!r}")
    print(f"  -> kismet.wifi.rf_status={wifi_rf_status!r} detail={wifi_rf_detail_final!r}")
    print("--- Bluetooth (Kismet API) ---")
    print(f"  bt_reason={bt_reason!r} bt_fallback_used={bt_fallback_used}")
    print(f"  bt_last_time_unix={bt_last_time!r} bt_human_time={bt_human_time!r}")
    print(f"  bt_last_unix (for freshness)={bt_last_unix!r}")
    print(f"  bt_rf_base={bt_rf_base!r} detail_base={bt_rf_detail_base!r}")
    print(f"  -> kismet.bluetooth.rf_status={bt_rf_status!r} detail={bt_rf_detail_final!r}")
    print("--- System / SDR ---")
    print(f"  kismet_active={kismet_active} overall_status (kismet.status)={overall_status!r}")
    print(f"  sdr_device_count={sdr_device_count} sdr_type={sdr_type!r} sdr_present={sdr_present}")
    print(f"  rtl_433 lines (systemctl)={rtl_count}")
    print("--- Zabbix payload (keys sent) ---")
    print(f"  kismet.rssi={tpms_rssi_sent!r}  (skipped if no TPMS row)")
    print(f"  kismet.last_time={tpms_last_time_sent!r}  (skipped if no TPMS row)")
    print(f"  kismet.rtl433.count={rtl_count!r}")
    print(f"  kismet.sdrplay.present={sdr_present!r}")
    print(f"  kismet.sdr.type={sdr_type!r}")
    print(f"  kismet.tpms.rf_status={tpms_rf_status!r}")
    print(f"  kismet.remarks={remarks!r}")
    print(f"  kismet.status={overall_status!r}")
    print(f"  kismet.wifi.rf_status={wifi_rf_status!r}")
    print(f"  kismet.wifi.last_time={wifi_last_time_value!r}")
    print(f"  kismet.bluetooth.rf_status={bt_rf_status!r}")
    print(f"  kismet.bluetooth.last_time={bt_last_time_value!r}")
    print("--- Host ---")
    if host_metrics:
        print(f"  boot_time (powered on)={host_metrics.get('boot_time')!r}")
        print(f"  uptime={host_metrics.get('uptime')!r}")
        print(f"  mem.available_mb (MemAvailable)={host_metrics.get('mem_available_mb')!r}")
        print(f"  ram.available_mb (MemFree)={host_metrics.get('ram_available_mb')!r}")
        print(
            "  -> kismet.system.boot_time, kismet.system.uptime, "
            "kismet.system.mem.available_mb, kismet.system.ram.available_mb"
        )
    else:
        print("  (no host_metrics)")
    print("--- System online (local agent.ping) ---")
    print(f"  system_online={system_online!r} detail={system_online_detail!r}")
    print("  -> kismet.system.online (1=agent.ping OK, 0=offline/unavailable)")
    print(f"--- 4DV endpoint summary ({FOUR_DV_DATA_AGE_URL}) ---")
    print(f"  fetch_detail={four_dv_summary_detail!r}")
    print(f"  -> kismet.4dv.endpoint.summary ({len(four_dv_summary)} chars)")
    if four_dv_summary:
        print(four_dv_summary)
    print("===========================")


# --------------------------
# Kismet API fetch (your logic kept)
# --------------------------
def fetch_latest_sensor_within(seconds_window: int):
    kismet_url = f"{KISMET_BASE}/devices/last-time/-{int(seconds_window)}/devices.json"
    payload = {
        "regex": [["kismet.device.base.type", "^Sensor$"]],
        "fields": [
            "kismet.device.base.last_time",
            "kismet.device.base.name",
            "kismet.device.base.frequency",
            "sensor.device",
        ],
    }
    try:
        response = requests.post(
            kismet_url,
            auth=(KISMET_USER, KISMET_PASS),
            json=payload,
            timeout=5,
        )
        if response.status_code != 200:
            return None, None, None, None, None, None, "API_ERROR"

        devices = response.json()
        if not devices:
            return None, None, None, None, None, None, "NO_DATA"

        latest_device = max(devices, key=lambda d: d.get("kismet.device.base.last_time", 0))
        last_time = latest_device.get("kismet.device.base.last_time")
        human_time = datetime.fromtimestamp(last_time).strftime("%Y-%m-%d %H:%M:%S") if last_time else None
        name = latest_device.get("kismet.device.base.name")

        frequency_khz = latest_device.get("kismet.device.base.frequency")
        frequency_mhz = round(frequency_khz / 1000) if isinstance(frequency_khz, (int, float)) else None

        if isinstance(frequency_khz, (int, float)):
            if 300_000 <= frequency_khz <= 320_000:
                band = "315MHz"
            elif 400_000 <= frequency_khz <= 450_000:
                band = "433MHz"
            else:
                band = "Unknown"
        else:
            band = "Unknown"

        rssi = None
        try:
            rssi = latest_device["sensor.device"]["sensor.device.common"]["sensor.device.rssi"]
        except Exception:
            pass

        return rssi, last_time, human_time, name, band, frequency_mhz, "OK"
    except Exception:
        return None, None, None, None, None, None, "API_ERROR"


def format_rssi_with_units(rssi) -> str:
    if rssi is None or rssi == "":
        return "N/A"
    return f"{rssi} dBm"


# --------------------------
# NEW: WiFi API fetch
# --------------------------
def fetch_latest_wifi_within(seconds_window: int):
    """
    Fetches latest WiFi device from Kismet API within time window.
    Returns: (last_time, human_time, reason)
    """
    kismet_url = f"{KISMET_BASE}/devices/last-time/-{int(seconds_window)}/devices.json"
    payload = {
        "regex": [["kismet.device.base.type", "^Wi-Fi"]],
        "fields": [
            "kismet.device.base.last_time",
            "kismet.device.base.name",
            "kismet.device.base.macaddr",
        ],
    }
    try:
        response = requests.post(
            kismet_url,
            auth=(KISMET_USER, KISMET_PASS),
            json=payload,
            timeout=5,
        )
        if response.status_code != 200:
            return None, None, "API_ERROR"

        devices = response.json()
        if not devices:
            return None, None, "NO_DATA"

        latest_device = max(devices, key=lambda d: d.get("kismet.device.base.last_time", 0))
        last_time = latest_device.get("kismet.device.base.last_time")
        human_time = datetime.fromtimestamp(last_time).strftime("%Y-%m-%d %H:%M:%S") if last_time else None

        return last_time, human_time, "OK"
    except Exception:
        return None, None, "API_ERROR"


# --------------------------
# NEW: Bluetooth API fetch
# --------------------------
def fetch_latest_bluetooth_within(seconds_window: int):
    """
    Fetches latest Bluetooth device from Kismet API within time window.
    Returns: (last_time, human_time, reason)
    """
    kismet_url = f"{KISMET_BASE}/devices/last-time/-{int(seconds_window)}/devices.json"
    payload = {
        "regex": [["kismet.device.base.type", "^BTLE"]],
        "fields": [
            "kismet.device.base.last_time",
            "kismet.device.base.name",
            "kismet.device.base.macaddr",
        ],
    }
    try:
        response = requests.post(
            kismet_url,
            auth=(KISMET_USER, KISMET_PASS),
            json=payload,
            timeout=5,
        )
        if response.status_code != 200:
            return None, None, "API_ERROR"

        devices = response.json()
        if not devices:
            return None, None, "NO_DATA"

        latest_device = max(devices, key=lambda d: d.get("kismet.device.base.last_time", 0))
        last_time = latest_device.get("kismet.device.base.last_time")
        human_time = datetime.fromtimestamp(last_time).strftime("%Y-%m-%d %H:%M:%S") if last_time else None

        return last_time, human_time, "OK"
    except Exception:
        return None, None, "API_ERROR"


# --------------------------
# NEW: Check WiFi RF status
# --------------------------
def get_wifi_rf_status() -> Tuple[str, str]:
    """
    Checks if WiFi RF is operational by:
    1. Checking kismet.service is active (running)
    2. Checking if kismet_cap_linux_wifi exists in cgroup
    Returns: (status, details)
    status: "OK" or "ERROR"
    """
    # Check if kismet service is active
    rc, out, _ = run_cmd(["systemctl", "is-active", "kismet.service"], timeout=10)
    if rc != 0 or out.strip() != "active":
        return "ERROR", "kismet.service not active"

    # Helper function to check systemctl status output (fallback method)
    def check_status_output():
        rc2, st, _ = run_cmd(["systemctl", "status", "kismet.service", "--no-pager"], timeout=10)
        if rc2 != 0:
            return None, "could not get systemctl status"
        if "kismet_cap_linux_wifi" in st:
            return "OK", "kismet_cap_linux_wifi found via status"
        return None, "kismet_cap_linux_wifi not found in status"

    # Get kismet's control group
    rc, cg, err = run_cmd(["systemctl", "show", "-p", "ControlGroup", "--value", "kismet.service"], timeout=10)
    cg = cg.strip()
    if rc != 0 or not cg:
        # Fallback: parse systemctl status
        status, details = check_status_output()
        if status:
            return status, details
        return "ERROR", details

    # Read process IDs from cgroup (cgroup v2)
    # Handle both /system.slice/kismet.service and system.slice/kismet.service formats
    cg_path = cg.lstrip("/")
    cgroup_procs = os.path.join("/sys/fs/cgroup", cg_path, "cgroup.procs")
    
    # Initialize pids list early
    pids = []
    
    # Also try unified cgroup v2 path if the above doesn't exist
    if not os.path.exists(cgroup_procs):
        # Try alternative path structure
        alt_path = os.path.join("/sys/fs/cgroup/unified", cg_path, "cgroup.procs")
        if os.path.exists(alt_path):
            cgroup_procs = alt_path
        else:
            # Fallback to status check if cgroup path doesn't exist
            status, details = check_status_output()
            if status:
                return status, details
            return "ERROR", f"missing {cgroup_procs} and {alt_path}"
    try:
        with open(cgroup_procs, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.isdigit():
                    pids.append(int(line))
    except Exception as e:
        # Fallback to status check if reading fails
        status, details = check_status_output()
        if status:
            return status, details
        return "ERROR", f"failed reading cgroup.procs: {e}"

    if not pids:
        # Fallback to status check if no PIDs found
        status, details = check_status_output()
        if status:
            return status, details
        return "ERROR", "no PIDs found in cgroup"

    # Check if kismet_cap_linux_wifi process exists
    for pid in pids:
        comm_path = f"/proc/{pid}/comm"
        cmdline_path = f"/proc/{pid}/cmdline"
        process_info = ""
        try:
            # Check comm file first (executable name)
            if os.path.exists(comm_path):
                with open(comm_path, "r", encoding="utf-8", errors="ignore") as f:
                    process_info = f.read().strip()
            
            # Also check cmdline (full command line, more reliable)
            if os.path.exists(cmdline_path):
                with open(cmdline_path, "rb") as f:
                    raw = f.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                    # Use full cmdline, not just first part, to catch the full path
                    if raw:
                        process_info = process_info + " " + raw if process_info else raw
        except Exception:
            continue

        # Check if kismet_cap_linux_wifi appears anywhere in the process info
        if "kismet_cap_linux_wifi" in process_info:
            return "OK", f"kismet_cap_linux_wifi found (pid {pid})"

    # Fallback to status check if process not found in cgroup
    status, details = check_status_output()
    if status:
        return status, details
    return "ERROR", "kismet_cap_linux_wifi not found in cgroup"


# --------------------------
# NEW: Check Bluetooth RF status
# --------------------------
def get_bluetooth_rf_status() -> Tuple[str, str]:
    """
    Checks if Bluetooth RF is operational by checking sniffle.service is active (running).
    Returns: (status, details)
    status: "OK" or "ERROR"
    """
    rc, out, _ = run_cmd(["systemctl", "is-active", "sniffle.service"], timeout=10)
    if rc != 0 or out.strip() != "active":
        return "ERROR", "sniffle.service not active"
    return "OK", "sniffle.service active"


# Match rtl_433 worker lines in `systemctl status kismet` (not kismet_cap_sdr_rtl433)
_RTL433_PROC_LINE = re.compile(r"\brtl_433\b")


def get_kismet_service_active() -> Tuple[str, str]:
    """kismet.status: OK only if kismet.service is active (running)."""
    rc, out, _ = run_cmd(["systemctl", "is-active", "kismet.service"], timeout=10)
    if rc == 0 and out.strip() == "active":
        return "OK", "kismet.service active"
    return "ERROR", "kismet.service not active"


def count_rtl433_in_kismet_systemctl_status() -> Tuple[int, str]:
    """
    Counts lines in `systemctl status kismet.service` that reference the rtl_433 process
    (tree lines like: ├─1793 rtl_433 -d ...).
    systemctl may return non-zero when unit is inactive but still prints status; we parse stdout.
    """
    rc, st, err = run_cmd(["systemctl", "status", "kismet.service", "--no-pager"], timeout=15)
    if not st.strip():
        return 0, f"empty systemctl status (rc={rc}): {err.strip() or 'no output'}"
    n = sum(1 for line in st.splitlines() if _RTL433_PROC_LINE.search(line))
    return n, "parsed systemctl status"


def count_sdrplay_devices_lsusb() -> Tuple[int, str]:
    """
    Counts SDRplay-class devices from lsusb (one per line).
    Matches RSPduo id 1df7:3020 or vendor name SDRplay.
    """
    try:
        rc, out, err = run_cmd(["lsusb"], timeout=10)
        if rc != 0:
            return 0, f"lsusb failed: {err.strip()}"
        n = 0
        sample_lines: List[str] = []
        for line in out.splitlines():
            if re.search(r"\b1df7:3020\b", line, re.IGNORECASE) or re.search(r"\bSDRplay\b", line, re.IGNORECASE):
                n += 1
                if len(sample_lines) < 3:
                    sample_lines.append(line.strip())
        if n == 0:
            return 0, "no SDRplay / 1df7:3020 in lsusb"
        return n, "; ".join(sample_lines) if sample_lines else f"{n} device(s)"
    except Exception as e:
        return 0, f"lsusb exception: {e}"


def sdr_type_label(device_count: int) -> str:
    """Zabbix kismet.sdr.type (source: lsusb device count)."""
    if device_count <= 0:
        return "No SDRplay"
    if device_count == 1:
        return "Single SDR"
    if device_count == 2:
        return "Dual SDR"
    return f"Multi SDR ({device_count})"


def get_tpms_rf_status(
    kismet_active: bool,
    sdr_device_count: int,
    rtl433_line_count: int,
) -> Tuple[str, str]:
    """
    Base hardware check for kismet.tpms.rf_status (before freshness merge):
    compare rtl_433 lines in systemctl status to USB layout.
    Single SDR (1 device) -> expect 2 rtl_433 lines; Dual (2 devices) -> 4; n devices -> 2*n.
    Returns OK or ERROR only; main() adds NOTICE via merge_rf_freshness.
    """
    if not kismet_active:
        return "ERROR", "kismet.service not active"
    if sdr_device_count <= 0:
        return "ERROR", "no SDRplay on USB (lsusb)"
    expected = 2 * sdr_device_count
    if rtl433_line_count == expected:
        return "OK", f"{rtl433_line_count} rtl_433 (expected {expected} for {sdr_device_count} SDR)"
    return "ERROR", f"expected {expected} rtl_433 in systemctl status, got {rtl433_line_count} (lsusb: {sdr_device_count} SDR)"


# --------------------------
# MAIN
# --------------------------
def main():
    normalize_zabbix_stale_argv()
    config_server, config_host = get_zabbix_config()

    parser = argparse.ArgumentParser(description="Kismet monitoring: collect metrics and send to Zabbix")
    parser.add_argument("-ip", "--ip", default=config_server, help="Zabbix server IP (overrides config)")
    parser.add_argument("--host", default=config_host, help="Zabbix hostname (overrides config)")
    parser.add_argument("--zbx-port", default=DEFAULT_ZABBIX_PORT, type=int, help="Zabbix server port (default 10051)")
    parser.add_argument(
        "--stale-after",
        default=os.getenv("KISMET_STALE_AFTER", "30m"),
        help="RF OK vs NOTICE: Kismet last_seen must be newer than this window (e.g. 30m, 2h). Env: KISMET_STALE_AFTER",
    )
    parser.add_argument(
        "stale_pos",
        nargs="?",
        default=None,
        help="Optional freshness window (e.g. 30m); overrides --stale-after if set",
    )
    parser.add_argument(
        "-debug",
        "--debug",
        action="store_true",
        help="Print all collected values and Zabbix-bound item keys",
    )
    args = parser.parse_args()

    stale_spec = args.stale_pos if args.stale_pos is not None else args.stale_after
    try:
        stale_after_sec = parse_stale_after(stale_spec)
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    zabbix_server = args.ip
    zabbix_port = args.zbx_port
    host_name = args.host

    # --- Kismet latest sensor data (TPMS) (kept) ---
    rssi, last_time, human_time, name, band, frequency_mhz, reason = fetch_latest_sensor_within(3600)
    fallback_used = False
    if reason == "NO_DATA":
        frssi, flast_time, fhuman_time, fname, fband, ffreq, freason = fetch_latest_sensor_within(31536000)
        if freason == "OK":
            rssi, last_time, human_time, name, band, frequency_mhz = frssi, flast_time, fhuman_time, fname, fband, ffreq
            fallback_used = True

    # --- NEW: WiFi monitoring ---
    wifi_last_time, wifi_human_time, wifi_reason = fetch_latest_wifi_within(10)
    wifi_fallback_used = False
    if wifi_reason == "NO_DATA":
        fwifi_time, fwifi_human, fwifi_reason = fetch_latest_wifi_within(31536000)
        if fwifi_reason == "OK":
            wifi_last_time, wifi_human_time = fwifi_time, fwifi_human
            wifi_fallback_used = True
    
    wifi_rf_base, wifi_rf_detail = get_wifi_rf_status()

    # --- NEW: Bluetooth monitoring ---
    bt_last_time, bt_human_time, bt_reason = fetch_latest_bluetooth_within(10)
    bt_fallback_used = False
    if bt_reason == "NO_DATA":
        fbt_time, fbt_human, fbt_reason = fetch_latest_bluetooth_within(31536000)
        if fbt_reason == "OK":
            bt_last_time, bt_human_time = fbt_time, fbt_human
            bt_fallback_used = True
    
    bt_rf_base, bt_rf_detail = get_bluetooth_rf_status()

    # kismet.service running (only input for kismet.status)
    overall_status, _ = get_kismet_service_active()
    kismet_active = overall_status == "OK"

    # SDR layout from lsusb
    sdr_device_count, _ = count_sdrplay_devices_lsusb()
    sdr_type = sdr_type_label(sdr_device_count)
    sdr_present = 1 if sdr_device_count > 0 else 0

    # rtl_433 lines under kismet in systemctl status (TPMS / SDR workers)
    rtl_count, _ = count_rtl433_in_kismet_systemctl_status()
    tpms_rf_base, tpms_rf_detail = get_tpms_rf_status(kismet_active, sdr_device_count, rtl_count)
    tpms_rf_detail_base = tpms_rf_detail
    wifi_rf_detail_base = wifi_rf_detail
    bt_rf_detail_base = bt_rf_detail

    tpms_last_unix: Optional[int] = (
        int(last_time) if last_time is not None and reason != "API_ERROR" else None
    )
    wifi_last_unix: Optional[int] = (
        int(wifi_last_time) if wifi_last_time is not None and wifi_reason != "API_ERROR" else None
    )
    bt_last_unix: Optional[int] = (
        int(bt_last_time) if bt_last_time is not None and bt_reason != "API_ERROR" else None
    )

    tpms_rf_status, tpms_rf_detail = merge_rf_freshness(
        tpms_rf_base, tpms_rf_detail, tpms_last_unix, stale_after_sec
    )
    wifi_rf_status, wifi_rf_detail = merge_rf_freshness(
        wifi_rf_base, wifi_rf_detail, wifi_last_unix, stale_after_sec
    )
    bt_rf_status, bt_rf_detail = merge_rf_freshness(
        bt_rf_base, bt_rf_detail, bt_last_unix, stale_after_sec
    )

    save_last_seen_state(state_file_path(), tpms_last_unix, wifi_last_unix, bt_last_unix)

    # remarks: API / fallback + RF lines (does not change kismet.status)
    remarks = "OK"
    if reason == "API_ERROR":
        remarks = "Kismet API error"
    elif fallback_used:
        remarks = "No sensor data in last hour (fallback used)"

    rf_bits: List[str] = []
    for label, st, det in (
        ("TPMS RF", tpms_rf_status, tpms_rf_detail),
        ("WiFi RF", wifi_rf_status, wifi_rf_detail),
        ("BT RF", bt_rf_status, bt_rf_detail),
    ):
        if st in ("ERROR", "NOTICE"):
            rf_bits.append(f"{label} {st}: {det}")
    if rf_bits:
        suffix = "; ".join(rf_bits)
        remarks = suffix if remarks == "OK" else f"{remarks}; {suffix}"

    wifi_last_time_value = wifi_human_time if wifi_human_time else "N/A"
    bt_last_time_value = bt_human_time if bt_human_time else "N/A"
    tpms_row_ok = rssi is not None and human_time is not None
    tpms_rssi_sent = format_rssi_with_units(rssi) if tpms_row_ok else None
    tpms_last_time_sent = human_time if tpms_row_ok else None

    host_m = collect_host_metrics()
    system_online, system_online_detail = check_zabbix_agent_ping()
    four_dv_summary, four_dv_summary_detail = build_4dv_endpoint_summary()

    if args.debug:
        print_debug_report(
            zabbix_server=zabbix_server,
            zabbix_port=zabbix_port,
            host_name=host_name,
            stale_spec=stale_spec,
            stale_after_sec=stale_after_sec,
            state_path=state_file_path(),
            rssi=rssi,
            last_time=last_time,
            human_time=human_time,
            name=name,
            band=band,
            frequency_mhz=frequency_mhz,
            reason=reason,
            fallback_used=fallback_used,
            wifi_last_time=wifi_last_time,
            wifi_human_time=wifi_human_time,
            wifi_reason=wifi_reason,
            wifi_fallback_used=wifi_fallback_used,
            bt_last_time=bt_last_time,
            bt_human_time=bt_human_time,
            bt_reason=bt_reason,
            bt_fallback_used=bt_fallback_used,
            wifi_rf_base=wifi_rf_base,
            wifi_rf_detail_base=wifi_rf_detail_base,
            bt_rf_base=bt_rf_base,
            bt_rf_detail_base=bt_rf_detail_base,
            overall_status=overall_status,
            kismet_active=kismet_active,
            sdr_device_count=sdr_device_count,
            sdr_type=sdr_type,
            sdr_present=sdr_present,
            rtl_count=rtl_count,
            tpms_rf_base=tpms_rf_base,
            tpms_rf_detail_base=tpms_rf_detail_base,
            tpms_last_unix=tpms_last_unix,
            wifi_last_unix=wifi_last_unix,
            bt_last_unix=bt_last_unix,
            tpms_rf_status=tpms_rf_status,
            tpms_rf_detail_final=tpms_rf_detail,
            wifi_rf_status=wifi_rf_status,
            wifi_rf_detail_final=wifi_rf_detail,
            bt_rf_status=bt_rf_status,
            bt_rf_detail_final=bt_rf_detail,
            remarks=remarks,
            wifi_last_time_value=wifi_last_time_value,
            bt_last_time_value=bt_last_time_value,
            tpms_rssi_sent=tpms_rssi_sent,
            tpms_last_time_sent=tpms_last_time_sent,
            host_metrics=host_m,
            system_online=system_online,
            system_online_detail=system_online_detail,
            four_dv_summary=four_dv_summary,
            four_dv_summary_detail=four_dv_summary_detail,
        )

    # --- Zabbix sends ---
    send_success = True

    # existing keys (only if we have data)
    if rssi is not None and human_time is not None:
        if not send_to_zabbix(zabbix_server, zabbix_port, host_name, "kismet.rssi", format_rssi_with_units(rssi)):
            send_success = False
        # Send only TPMS last_time (WiFi and Bluetooth are sent separately)
        if not send_to_zabbix(zabbix_server, zabbix_port, host_name, "kismet.last_time", human_time):
            send_success = False

    # NEW items
    if not send_to_zabbix(zabbix_server, zabbix_port, host_name, "kismet.rtl433.count", str(rtl_count)):
        send_success = False
    if not send_to_zabbix(zabbix_server, zabbix_port, host_name, "kismet.sdrplay.present", str(sdr_present)):
        send_success = False
    if not send_to_zabbix(zabbix_server, zabbix_port, host_name, "kismet.sdr.type", sdr_type):
        send_success = False
    if not send_to_zabbix(zabbix_server, zabbix_port, host_name, "kismet.tpms.rf_status", tpms_rf_status):
        send_success = False
    if not send_to_zabbix(zabbix_server, zabbix_port, host_name, "kismet.remarks", remarks):
        send_success = False

    # kismet.service active only
    if not send_to_zabbix(zabbix_server, zabbix_port, host_name, "kismet.status", overall_status):
        send_success = False

    # NEW: WiFi RF status and last time (optional keys - may not be configured in Zabbix)
    if not send_to_zabbix(zabbix_server, zabbix_port, host_name, "kismet.wifi.rf_status", wifi_rf_status):
        send_success = False
    # Always send last_time value (use "N/A" if not available)
    if not send_to_zabbix(zabbix_server, zabbix_port, host_name, "kismet.wifi.last_time", wifi_last_time_value):
        # Don't fail overall status for optional keys that may not be configured in Zabbix
        pass

    # NEW: Bluetooth RF status and last time (optional keys - may not be configured in Zabbix)
    if not send_to_zabbix(zabbix_server, zabbix_port, host_name, "kismet.bluetooth.rf_status", bt_rf_status):
        send_success = False
    # Always send last_time value (use "N/A" if not available)
    if not send_to_zabbix(zabbix_server, zabbix_port, host_name, "kismet.bluetooth.last_time", bt_last_time_value):
        # Don't fail overall status for optional keys that may not be configured in Zabbix
        pass

    if not send_host_metrics_to_zabbix(zabbix_server, zabbix_port, host_name, host_m):
        send_success = False

    if not send_to_zabbix(
        zabbix_server, zabbix_port, host_name, "kismet.system.online", str(system_online)
    ):
        send_success = False

    if not send_to_zabbix(
        zabbix_server, zabbix_port, host_name, "kismet.4dv.endpoint.summary", four_dv_summary
    ):
        send_success = False

    print(f"Latest: {human_time} | RSSI: {rssi} | rtl_433 (systemctl): {rtl_count} | SDR: {sdr_type} (lsusb x{sdr_device_count})")
    print(f"kismet.status: {overall_status} | kismet.tpms.rf_status: {tpms_rf_status}")
    print(f"WiFi RF: {wifi_rf_status} | WiFi Last: {wifi_human_time or 'N/A'} | BT RF: {bt_rf_status} | BT Last: {bt_human_time or 'N/A'}")
    _boot = host_m.get("boot_time")
    _up = host_m.get("uptime")
    _ma = host_m.get("mem_available_mb")
    _ra = host_m.get("ram_available_mb")
    if _boot is None and _up is None and _ma is None and _ra is None:
        print("Host: (no /proc metrics — non-Linux or unreadable)")
    else:
        print(
            f"Host: powered on={_boot or '?'} | uptime={_up or '?'} | "
            f"available memory={_ma if _ma is not None else '?'} MB | "
            f"available RAM={_ra if _ra is not None else '?'} MB"
        )
    print(f"System online (agent.ping): {system_online} ({system_online_detail})")
    print(f"4DV endpoint summary: {four_dv_summary_detail} ({len(four_dv_summary)} chars)")
    print(f"Remarks: {remarks}")
    print(overall_status if send_success else "ERROR")


if __name__ == "__main__":
    main()