#!/usr/bin/env python3
import os
import re
import json
import sys
import time
import argparse
import subprocess
import traceback
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Set


STATE_DIR = "/var/lib/kismet_monitor"
STATE_FILE = os.path.join(STATE_DIR, "sdrplay_recovery_state.json")

SDR_VENDOR_PRODUCT = "1df7:3020"
RTL433_PER_SDR = 2
DEFAULT_HEALTH_CHECK_SLEEP = 10.0
DEFAULT_SNIFFLE_RESTART_SLEEP = 8.0
DEFAULT_SYSTEMCTL_STOP_TIMEOUT = 90
DEFAULT_SYSTEMCTL_TIMEOUT = 60
SYSTEMCTL_CFG = {
    "stop_timeout": DEFAULT_SYSTEMCTL_STOP_TIMEOUT,
    "timeout": DEFAULT_SYSTEMCTL_TIMEOUT,
}
DEFAULT_SDRPLAY_SERVICE = "sdrplay.service"
DEFAULT_KISMET_SERVICE = "kismet.service"
DEFAULT_SNIFFLE_SERVICE = "sniffle.service"

KISMET_CAPTURE_PROCESSES = ("rtl_433", "kismet_cap_sdr_rtl433")
KISMET_REMOTE_CAPTURE_PORT = 3501
EXECUTION_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sdrplay_recover_log.txt")
LAST_RESULT: Optional[Dict] = None
DEBUG = False
_T0 = time.monotonic()


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def dbg(msg: str):
    """Print a timestamped debug line to stderr (only when --debug is set).

    Goes to stderr so it never corrupts --json-output stdout used by callers.
    """
    if not DEBUG:
        return
    elapsed = time.monotonic() - _T0
    sys.stderr.write(f"[DEBUG {now_str()} +{elapsed:7.2f}s] {msg}\n")
    sys.stderr.flush()


def log_execution(result: Optional[Dict], exit_code: int):
    """
    Append one simple line per script execution:
    timestamp | exit_code | ok/failed | summary
    """
    ts = now_str()
    if result:
        ok = bool(result.get("ok", False))
        status = "ok" if ok else "failed"
        summary = str(result.get("summary", "")).replace("\n", " ").strip()
    else:
        status = "failed" if exit_code else "ok"
        summary = "No result emitted"

    line = f"{ts} | exit_code={exit_code} | {status} | {summary}\n"
    try:
        with open(EXECUTION_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        # Do not break recovery flow if logging fails.
        pass


def privileged_cmd(*parts: str) -> List[str]:
    """Run as root directly; use sudo only when not already root."""
    cmd = list(parts)
    if os.geteuid() != 0:
        return ["sudo", *cmd]
    return cmd


def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    printable = " ".join(cmd)
    dbg(f"RUN (timeout={timeout}s): {printable}")
    t_start = time.monotonic()
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        dt = time.monotonic() - t_start
        dbg(
            f"  -> rc={p.returncode} in {dt:.2f}s"
            f"{_dbg_trunc(' | stdout: ', p.stdout)}{_dbg_trunc(' | stderr: ', p.stderr)}"
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout if isinstance(e.stdout, str) else (
            (e.stdout or b"").decode(errors="replace") if e.stdout else ""
        )
        stderr = e.stderr if isinstance(e.stderr, str) else (
            (e.stderr or b"").decode(errors="replace") if e.stderr else ""
        )
        dbg(f"  -> TIMEOUT after {timeout}s: {printable}")
        return -9, stdout, f"{stderr} [timed out after {timeout}s]".strip()


def _dbg_trunc(prefix: str, text: Optional[str], limit: int = 300) -> str:
    """Format optional command output for a single-line debug message."""
    if not DEBUG or not text:
        return ""
    flat = " ".join(text.split())
    if not flat:
        return ""
    if len(flat) > limit:
        flat = flat[:limit] + "...(truncated)"
    return f"{prefix}{flat}"


def sleep_dbg(seconds: float, reason: str = ""):
    """time.sleep() with a debug trace so gaps in the timeline are explained."""
    label = f" ({reason})" if reason else ""
    dbg(f"SLEEP {seconds:.1f}s{label}")
    time.sleep(seconds)


def _systemctl_output_text(out: str, err: str) -> str:
    return (err.strip() or out.strip() or "").strip()


def ensure_state_dir():
    os.makedirs(STATE_DIR, exist_ok=True)


def load_state() -> Dict:
    ensure_state_dir()
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state: Dict):
    ensure_state_dir()
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, STATE_FILE)


def parse_uhubctl_devices(uhubctl_output: str) -> List[Dict]:
    """
    Parse 'uhubctl' output and return list of SDRplay devices *if SDRplay appears directly* on a controllable port.
    NOTE: If SDRplay is behind a 'ganged' hub, uhubctl will usually show only the downstream HUB (e.g. 05e3:0610),
          not the SDRplay itself. In that case this returns [] and we use the fallback.
    """
    devices = []
    hub_line = ""
    hub_id = None

    hub_re = re.compile(r"^Current status for hub\s+(\d+)\s+\[", re.IGNORECASE)
    port_re = re.compile(r"^\s*Port\s+(\d+):\s+(.*)$", re.IGNORECASE)

    for line in uhubctl_output.splitlines():
        line = line.rstrip("\n")
        m = hub_re.match(line)
        if m:
            hub_id = int(m.group(1))
            hub_line = line.strip()
            continue

        m2 = port_re.match(line)
        if m2 and hub_id is not None:
            port = int(m2.group(1))
            rest = m2.group(2)

            if SDR_VENDOR_PRODUCT.lower() in rest.lower() or "sdrplay" in rest.lower() or "rspduo" in rest.lower():
                serial = None
                br = re.search(r"\[(.*?)\]", rest)
                if br:
                    tokens = br.group(1).split()
                    if len(tokens) >= 2 and tokens[0].lower() == SDR_VENDOR_PRODUCT:
                        serial = tokens[-1]
                devices.append({
                    "hub": hub_id,
                    "port": port,
                    "serial": serial,
                    "hub_line": hub_line,
                    "port_line": line.strip(),
                    "mode": "direct_sdrplay",
                })

    return devices


def parse_uhubctl_ports(uhubctl_output: str) -> List[Dict]:
    """
    Parse all hubs/ports from uhubctl output. Used by fallback to find which upstream port
    the downstream HUB (e.g. 05e3:0610) is connected to.
    """
    ports = []
    hub_id = None
    hub_line = ""

    hub_re = re.compile(r"^Current status for hub\s+(\d+)\s+\[", re.IGNORECASE)
    port_re = re.compile(r"^\s*Port\s+(\d+):\s+(.*)$", re.IGNORECASE)

    for line in uhubctl_output.splitlines():
        line = line.rstrip("\n")
        m = hub_re.match(line)
        if m:
            hub_id = int(m.group(1))
            hub_line = line.strip()
            continue

        m2 = port_re.match(line)
        if m2 and hub_id is not None:
            ports.append({
                "hub": hub_id,
                "port": int(m2.group(1)),
                "rest": m2.group(2),
                "hub_line": hub_line,
                "port_line": line.strip(),
            })

    return ports


def uhubctl_power(hub: int, port: int, action: str, timeout: int = 20) -> Tuple[bool, str]:
    rc, out, err = run_cmd(
        privileged_cmd("uhubctl", "-l", str(hub), "-p", str(port), "-a", action),
        timeout=timeout,
    )
    if rc != 0:
        return False, f"uhubctl -l {hub} -p {port} -a {action} failed: {_systemctl_output_text(out, err)}"
    return True, out.strip() or f"uhubctl {action} ok"


def systemctl(
    action: str,
    service: str,
    timeout: Optional[int] = None,
    stop_timeout: Optional[int] = None,
) -> Tuple[bool, str]:
    if timeout is None:
        if action in ("stop", "restart"):
            timeout = stop_timeout if stop_timeout is not None else SYSTEMCTL_CFG["stop_timeout"]
        else:
            timeout = SYSTEMCTL_CFG["timeout"]

    cmd = privileged_cmd("systemctl", action, service)
    rc, out, err = run_cmd(cmd, timeout=timeout)
    text = _systemctl_output_text(out, err)

    if rc == -9 and action == "stop":
        run_cmd(privileged_cmd("systemctl", "kill", service), timeout=15)
        time.sleep(2)
        rc, out, err = run_cmd(cmd, timeout=30)
        text = _systemctl_output_text(out, err)
        if rc == 0:
            return True, f"systemctl stop {service} ok (after kill)"
        if rc == -9:
            return False, f"systemctl stop {service} timed out after {timeout}s (kill did not help)"

    if rc == -9:
        return False, f"systemctl {action} {service} timed out after {timeout}s"
    if rc != 0:
        return False, f"systemctl {action} {service} failed: {text}"
    return True, f"systemctl {action} {service} ok"


def kill_kismet_capture_processes() -> Tuple[bool, str]:
    """
    Kill stray rtl_433 / kismet_cap_sdr_rtl433 before restarting kismet.

    Escalates SIGTERM -> SIGKILL: capture processes wedged in USB/SoapySDR I/O
    ignore SIGTERM and survive (they can also inherit and hold kismet's
    remote-capture socket on port 3501, which then blocks every kismet start).
    """
    messages = []
    for name in KISMET_CAPTURE_PROCESSES:
        run_cmd(["bash", "-lc", f"pkill -x {name} 2>/dev/null || true"], timeout=10)
        messages.append(f"pkill -x {name}")
    time.sleep(1)

    # Escalate to SIGKILL for anything that ignored SIGTERM.
    killed_hard = []
    for name in KISMET_CAPTURE_PROCESSES:
        rc, out, _ = run_cmd(["bash", "-lc", f"pgrep -x {name} || true"], timeout=10)
        if (out or "").strip():
            run_cmd(["bash", "-lc", f"pkill -9 -x {name} 2>/dev/null || true"], timeout=10)
            killed_hard.append(name)
    if killed_hard:
        messages.append(f"SIGKILL escalation: {', '.join(killed_hard)}")
        dbg(f"SIGKILL escalation for stray capture procs: {killed_hard}")
        time.sleep(1)

    return True, "; ".join(messages)


def reset_failed(service: str) -> Tuple[bool, str]:
    """Clear a unit's failed / 'start request repeated too quickly' lockout."""
    rc, out, err = run_cmd(privileged_cmd("systemctl", "reset-failed", service), timeout=15)
    ok = rc == 0
    dbg(f"reset-failed {service} rc={rc}")
    return ok, f"systemctl reset-failed {service} {'ok' if ok else 'rc=' + str(rc)}"


def free_remote_capture_port(port: int = KISMET_REMOTE_CAPTURE_PORT) -> Tuple[bool, str]:
    """
    Ensure the kismet remote-capture TCP port is free.

    A stray capture process can inherit and hold this socket after kismet dies,
    causing 'bind: Address already in use' on every subsequent start. SIGKILL the
    holder(s) via fuser, then confirm the port is released.
    """
    holder = port_holder(port)
    if not holder:
        return True, f"port {port} already free"

    dbg(f"port {port} held by [{holder}] -> SIGKILL holder via fuser")
    run_cmd(["bash", "-lc", f"fuser -k {port}/tcp 2>/dev/null || true"], timeout=10)
    time.sleep(1)

    holder2 = port_holder(port)
    if holder2:
        return False, f"port {port} STILL held after fuser -k: {holder2}"
    return True, f"port {port} freed (was held by: {holder})"


def count_sdrplay_devices() -> int:
    return len(lsusb_find_sdrplay())


def expected_rtl433_count(sdr_count: int, override: Optional[int] = None) -> int:
    """2 rtl_433 instances per SDRplay (1 SDR -> 2, 2 SDRs -> 4)."""
    if override is not None:
        return override
    if sdr_count <= 0:
        return 0
    return sdr_count * RTL433_PER_SDR


def health_check_kismet(
    kismet_service: str,
    expect_rtl433: int,
    wait_seconds: float = DEFAULT_HEALTH_CHECK_SLEEP,
) -> Tuple[bool, int, str]:
    sleep_dbg(wait_seconds, "health-check warm-up before counting rtl_433")
    kismet_ok, rtl_count, detail = get_kismet_state_and_rtl433_count(kismet_service)
    detail = f"after {wait_seconds}s wait: {detail} (expected >= {expect_rtl433})"
    return kismet_ok, rtl_count, detail


def start_kismet(kismet_service: str, actions: List[str]) -> Tuple[bool, str]:
    # 1. Kill stray capture processes (TERM then KILL).
    ok, msg = kill_kismet_capture_processes()
    actions.append(msg)

    # 2. Free the remote-capture port if a stray process is still holding it.
    ok_port, port_msg = free_remote_capture_port()
    actions.append(port_msg)
    if not ok_port:
        dbg(f"WARNING: {port_msg}")

    # 3. Clear any failed / rapid-restart lockout so the start isn't silently refused.
    _, rf_msg = reset_failed(kismet_service)
    actions.append(rf_msg)

    return systemctl("start", kismet_service)


def is_service_active(service: str) -> bool:
    rc, out, _ = run_cmd(["systemctl", "is-active", service], timeout=10)
    return rc == 0 and out.strip() == "active"


def process_in_service_cgroup(
    service: str,
    needle: str,
) -> Tuple[bool, str]:
    """
    True if any process in the service cgroup has `needle` in its cmdline.
    Falls back to systemctl status text if cgroup cannot be read.
    """
    if not is_service_active(service):
        return False, f"{service} not active"

    rc, cg, _ = run_cmd(
        ["systemctl", "show", "-p", "ControlGroup", "--value", service],
        timeout=10,
    )
    cg = (cg or "").strip()
    if rc == 0 and cg:
        cgroup_procs = os.path.join("/sys/fs/cgroup", cg.lstrip("/"), "cgroup.procs")
        if os.path.exists(cgroup_procs):
            try:
                with open(cgroup_procs, "r", encoding="utf-8", errors="ignore") as f:
                    pids = [int(x.strip()) for x in f if x.strip().isdigit()]
            except OSError:
                pids = []
            sample: List[str] = []
            for pid in pids:
                cmdline_path = f"/proc/{pid}/cmdline"
                try:
                    with open(cmdline_path, "rb") as f:
                        raw = f.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                except OSError:
                    continue
                if not raw:
                    continue
                if len(sample) < 4:
                    sample.append(raw[:120])
                if needle in raw:
                    return True, f"{needle} found under {service} (pid {pid})"
            detail = f"{needle} missing under {service} cgroup (pids={len(pids)})"
            if sample:
                detail += f"; procs: {'; '.join(sample)}"
            return False, detail

    rc, st, _ = run_cmd(
        ["systemctl", "status", service, "--no-pager"],
        timeout=10,
    )
    if needle in (st or ""):
        return True, f"{needle} found in systemctl status of {service}"
    return False, f"{needle} not found in {service} status (active alone is not enough)"


def sniffle_receiver_running(sniffle_service: str) -> Tuple[bool, str]:
    """
    Healthy sniffle needs sniff_receiver.py under the unit cgroup.

    systemctl can report active while only sniffle_kismet_bridge.py remains
    (receiver dead -> bridge gets Connection refused to tcp://127.0.0.1:9001).
    """
    return process_in_service_cgroup(sniffle_service, "sniff_receiver")


def wifi_capture_running(kismet_service: str) -> Tuple[bool, str]:
    """
    Healthy WiFi RF under Kismet needs kismet_cap_linux_wifi in the unit cgroup.
    Unit can be active while the wifi source has died / never started.
    """
    return process_in_service_cgroup(kismet_service, "kismet_cap_linux_wifi")


def ensure_sniffle_active(
    sniffle_service: str,
    actions: List[str],
    restart_wait: float = DEFAULT_SNIFFLE_RESTART_SLEEP,
    max_attempts: int = 3,
) -> Tuple[bool, str]:
    """
    Ensure sniffle is truly healthy: unit active AND sniff_receiver.py present.
    Restarts when inactive or when only the bridge is left running.

    Retries a few times: sniff_receiver can fail once on /dev/ttyUSB0 (permission
    or device not ready after USB events) and come up cleanly on a later restart.
    """
    ok_recv, detail = sniffle_receiver_running(sniffle_service)
    if ok_recv:
        return True, detail

    last_detail = detail
    for attempt in range(1, max_attempts + 1):
        actions.append(
            f"{sniffle_service} unhealthy ({last_detail}), restart attempt {attempt}/{max_attempts}"
        )
        ok, msg = systemctl("restart", sniffle_service)
        actions.append(msg)
        if not ok:
            last_detail = f"{sniffle_service} restart failed: {msg}"
            sleep_dbg(2.0, "brief pause after failed systemctl restart")
            continue

        # Receiver can lag the unit "active" status; wait and re-poll.
        time.sleep(restart_wait)
        ok_recv, last_detail = sniffle_receiver_running(sniffle_service)
        if ok_recv:
            return True, f"{sniffle_service} healthy after restart attempt {attempt}: {last_detail}"

        extra = max(3.0, float(restart_wait) * 0.5)
        sleep_dbg(extra, f"sniffle settle after attempt {attempt} (no sniff_receiver yet)")
        ok_recv, last_detail = sniffle_receiver_running(sniffle_service)
        if ok_recv:
            return True, f"{sniffle_service} healthy after settle on attempt {attempt}: {last_detail}"

        if attempt < max_attempts:
            sleep_dbg(3.0, "pause before next sniffle restart attempt")

    return False, f"{sniffle_service} still unhealthy after {max_attempts} restarts: {last_detail}"


def format_side_health(sniffle_ok: Optional[bool], sniffle_detail: str, wifi_ok: Optional[bool]) -> str:
    parts = []
    if sniffle_ok is not None:
        parts.append(f"sniffle={'OK' if sniffle_ok else 'FAILED'}")
        if sniffle_detail:
            parts.append(f"({sniffle_detail})")
    if wifi_ok is not None:
        parts.append(f"wifi={'OK' if wifi_ok else 'MISSING'}")
    return " ".join(parts) if parts else ""


def ensure_wifi_capture(
    kismet_service: str,
    actions: List[str],
    restart_wait: float = DEFAULT_HEALTH_CHECK_SLEEP,
) -> Tuple[bool, str]:
    """
    Ensure kismet has kismet_cap_linux_wifi running.
    Restarts kismet (via start_kismet) when the capture process is missing.
    """
    ok_wifi, detail = wifi_capture_running(kismet_service)
    if ok_wifi:
        return True, detail

    actions.append(f"WiFi capture unhealthy ({detail}), restarting {kismet_service}")
    # Full stop then clean start so sources re-spawn.
    ok, msg = systemctl("stop", kismet_service)
    actions.append(msg)
    sleep_dbg(2, "settle after stop for wifi re-capture")
    ok, msg = start_kismet(kismet_service, actions)
    actions.append(msg)
    if not ok:
        return False, f"{kismet_service} restart for wifi failed: {msg}"

    time.sleep(restart_wait)
    ok_wifi, detail_after = wifi_capture_running(kismet_service)
    if ok_wifi:
        return True, f"WiFi healthy after kismet restart: {detail_after}"

    return False, f"WiFi still unhealthy after kismet restart: {detail_after}"


def get_kismet_state_and_rtl433_count(kismet_service: str) -> Tuple[bool, int, str]:
    """
    Returns (kismet_ok, rtl_433_count, details).
    """
    rc, out, _ = run_cmd(["systemctl", "is-active", kismet_service], timeout=10)
    if rc != 0 or out.strip() != "active":
        return False, 0, f"{kismet_service} not active"

    # Count rtl_433 instances by process name.
    rc, out, _ = run_cmd(["bash", "-lc", "pgrep -x rtl_433 | wc -l"], timeout=10)
    if rc != 0 and not out.strip():
        return True, 0, "failed to count rtl_433"
    try:
        count = int(out.strip())
    except ValueError:
        count = 0
    return True, count, f"{kismet_service} active, rtl_433_count={count}"


def port_holder(port: int) -> str:
    """Return a description of any process listening on the given TCP port (empty if free)."""
    rc, out, err = run_cmd(["bash", "-lc", f"ss -ltnp 2>/dev/null | grep ':{port} ' || true"], timeout=10)
    text = (out or "").strip()
    if text:
        return text
    # Fallback to fuser if ss did not show a holder.
    rc, out, err = run_cmd(["bash", "-lc", f"fuser {port}/tcp 2>/dev/null || true"], timeout=10)
    return (out or "").strip()


def diagnose_kismet_failure(kismet_service: str, actions: List[str]):
    """
    When a kismet health check fails, capture *why* into the result + debug stream:
    service sub-state, the most relevant recent journal lines (FATAL/ERROR/leftover),
    leftover capture processes, and who is holding the remote-capture port (3501).
    """
    dbg("=== KISMET FAILURE DIAGNOSIS ===")

    rc, out, _ = run_cmd(["systemctl", "show", kismet_service,
                          "-p", "ActiveState,SubState,Result,ExecMainStatus,NRestarts"], timeout=10)
    state_line = " ".join((out or "").split())
    actions.append(f"DIAG kismet state: {state_line}")
    dbg(f"kismet state: {state_line}")

    rc, out, _ = run_cmd(
        ["bash", "-lc",
         f"journalctl -u {kismet_service} -n 60 --no-pager 2>/dev/null | "
         "grep -iE 'fatal|error|address already in use|left-over|leftover|repeated too quickly|"
         "remains running|cannot continue' | tail -n 15 || true"],
        timeout=15,
    )
    for line in (out or "").splitlines():
        line = line.strip()
        if line:
            actions.append(f"DIAG journal: {line}")
            dbg(f"journal: {line}")

    holder = port_holder(KISMET_REMOTE_CAPTURE_PORT)
    if holder:
        actions.append(f"DIAG port {KISMET_REMOTE_CAPTURE_PORT} in use by: {holder}")
        dbg(f"port {KISMET_REMOTE_CAPTURE_PORT} HOLDER: {holder}")
    else:
        actions.append(f"DIAG port {KISMET_REMOTE_CAPTURE_PORT} is free")
        dbg(f"port {KISMET_REMOTE_CAPTURE_PORT} is free")

    rc, out, _ = run_cmd(["bash", "-lc", "pgrep -a kismet; pgrep -a rtl_433; pgrep -a kismet_cap_sdr_rtl433"], timeout=10)
    procs = [l.strip() for l in (out or "").splitlines() if l.strip()]
    if procs:
        actions.append(f"DIAG leftover procs: {len(procs)} -> {'; '.join(procs)[:300]}")
        for p in procs:
            dbg(f"leftover proc: {p}")
    else:
        actions.append("DIAG leftover procs: none")
        dbg("leftover procs: none")
    dbg("=== END KISMET FAILURE DIAGNOSIS ===")


def soapy_verify() -> Tuple[bool, str]:
    rc, out, err = run_cmd(["SoapySDRUtil", "--find", "--args=driver=sdrplay"], timeout=30)
    text = (out + "\n" + err).strip()
    if "No devices found" in text:
        return False, "SoapySDRUtil: No devices found"
    if rc != 0:
        return False, f"SoapySDRUtil error: {text[:200]}"
    return True, "SoapySDRUtil: SDRplay detected"


def shutil_which(binary: str) -> bool:
    rc, out, _ = run_cmd(["bash", "-lc", f"command -v {binary} >/dev/null 2>&1; echo $?"], timeout=10)
    return out.strip() == "0"


# -----------------------------
# Fallback helpers (Hub search)
# -----------------------------
def lsusb_find_sdrplay() -> List[Tuple[int, int]]:
    """
    Returns list of (bus, device) numbers for SDRplay devices from lsusb.
    """
    rc, out, err = run_cmd(["bash", "-lc", f"lsusb -d {SDR_VENDOR_PRODUCT}"], timeout=15)
    text = (out + "\n" + err).strip()
    if rc != 0 or not text:
        return []

    found: List[Tuple[int, int]] = []
    for line in text.splitlines():
        # Example: Bus 002 Device 021: ID 1df7:3020 SDRplay RSPduo
        m = re.search(r"Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-fA-F]{4}:[0-9a-fA-F]{4})", line)
        if m and m.group(3).lower() == SDR_VENDOR_PRODUCT:
            found.append((int(m.group(1)), int(m.group(2))))
    return found


def udev_sysfs_name_for_busdev(bus: int, dev: int) -> Optional[str]:
    """
    Maps /dev/bus/usb/BBB/DDD to a sysfs name like '2-1.2' using udevadm.
    """
    node = f"/dev/bus/usb/{bus:03d}/{dev:03d}"
    rc, out, err = run_cmd(["bash", "-lc", f"udevadm info -q path -n {node} 2>/dev/null"], timeout=10)
    path = (out or "").strip()
    if rc != 0 or not path:
        return None
    # path ends with /usbX/<sysfsname> or similar
    return os.path.basename(path)


def read_sysfs_attr(devname: str, attr: str) -> Optional[str]:
    p = os.path.join("/sys/bus/usb/devices", devname, attr)
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return f.read().strip()
    except Exception:
        return None


def find_parent_hub_vidpid(sys_dev: str) -> Optional[str]:
    """
    Given a sysfs device name like '2-1.2' (SDRplay), walk up to find the nearest
    non-root HUB device. Returns 'vvvv:pppp' (e.g. '05e3:0610').

    We treat a hub as:
      - bDeviceClass == '09' OR
      - has 'maxchild' attribute
    We skip Linux root hubs (idVendor == 1d6b).
    """
    cur = sys_dev
    for _ in range(12):  # sufficient depth
        # Parent is everything before last '.'
        # Example: 2-1.2 -> 2-1  (this is typically the external hub)
        if "." in cur:
            parent = cur.rsplit(".", 1)[0]
        else:
            # already at something like '2-1' or 'usb2'
            parent = None

        if not parent:
            return None

        idv = read_sysfs_attr(parent, "idVendor")
        idp = read_sysfs_attr(parent, "idProduct")
        bcls = read_sysfs_attr(parent, "bDeviceClass")
        is_hubish = (bcls == "09") or os.path.exists(os.path.join("/sys/bus/usb/devices", parent, "maxchild"))

        if idv and idp and is_hubish and idv.lower() != "1d6b":
            return f"{idv.lower()}:{idp.lower()}"

        cur = parent

    return None


def sdrplay_serial_for_busdev(bus: int, dev: int) -> Optional[str]:
    sysname = udev_sysfs_name_for_busdev(bus, dev)
    if not sysname:
        return None
    return read_sysfs_attr(sysname, "serial")


def build_reset_targets(
    uhubctl_output: str,
    serial_filter: Optional[str] = None,
) -> Tuple[List[Dict], List[str]]:
    """
    Build USB power-cycle targets for every SDRplay from lsusb.

    Mixed Pi 5 topology (e.g. one SDR on USB3 port, one behind a hub on the other port):
      - SDR behind external hub -> hub_fallback (upstream port for that hub)
      - SDR on host port (no external parent hub) -> direct_sdrplay port from uhubctl
    """
    log: List[str] = []
    sdr_busdev = lsusb_find_sdrplay()
    if not sdr_busdev:
        return [], ["No SDRplay found via lsusb"]

    direct_list = parse_uhubctl_devices(uhubctl_output)
    assigned_direct: Set[Tuple[int, int]] = set()
    targets: List[Dict] = []
    seen_hub_fallback: Set[str] = set()
    seen_direct: Set[Tuple[int, int]] = set()

    for bus, dev in sdr_busdev:
        sysname = udev_sysfs_name_for_busdev(bus, dev)
        sdr_serial = sdrplay_serial_for_busdev(bus, dev)
        if serial_filter and sdr_serial != serial_filter:
            continue

        parent_hub = find_parent_hub_vidpid(sysname) if sysname else None
        log.append(
            f"SDR bus {bus:03d} dev {dev:03d} sys={sysname or '?'} "
            f"serial={sdr_serial or '?'} parent_hub={parent_hub or 'none (host port)'}"
        )

        if parent_hub:
            if parent_hub in seen_hub_fallback:
                log.append(f"  hub_fallback {parent_hub}: already targeted")
                continue
            up = find_upstream_port_for_downstream_hub(uhubctl_output, parent_hub)
            if not up:
                log.append(f"  hub_fallback {parent_hub}: not found in uhubctl output")
                continue
            seen_hub_fallback.add(parent_hub)
            up["sdr_serial"] = sdr_serial
            targets.append(up)
            log.append(
                f"  -> hub_fallback upstream hub {up['hub']} port {up['port']} "
                f"(downstream {parent_hub})"
            )
            continue

        matched = None
        if sdr_serial:
            for d in direct_list:
                key = (d["hub"], d["port"])
                if key in assigned_direct:
                    continue
                if d.get("serial") == sdr_serial:
                    matched = d
                    assigned_direct.add(key)
                    break

        if not matched:
            for d in direct_list:
                key = (d["hub"], d["port"])
                if key not in assigned_direct:
                    matched = d
                    assigned_direct.add(key)
                    log.append("  -> direct: matched unassigned uhubctl SDRplay port")
                    break

        if not matched:
            log.append("  -> direct: no controllable uhubctl port for this SDR")
            continue

        key = (matched["hub"], matched["port"])
        if key in seen_direct:
            continue
        seen_direct.add(key)
        matched = dict(matched)
        matched["sdr_serial"] = sdr_serial
        targets.append(matched)
        log.append(f"  -> direct_sdrplay hub {matched['hub']} port {matched['port']}")

    return targets, log


def find_upstream_port_for_downstream_hub(uhubctl_output: str, hub_vidpid: str) -> Optional[Dict]:
    """
    Given uhubctl output + a downstream hub vid:pid (e.g. 05e3:0610),
    find the upstream controllable port line that contains it, and return:
      {"hub": <hub_id>, "port": <port>, "port_line": "...", "hub_line": "...", "mode": "hub_fallback"}
    """
    hub_vidpid = hub_vidpid.lower()
    for p in parse_uhubctl_ports(uhubctl_output):
        if hub_vidpid in p["rest"].lower():
            return {
                "hub": p["hub"],
                "port": p["port"],
                "serial": None,
                "hub_line": p["hub_line"],
                "port_line": p["port_line"],
                "mode": "hub_fallback",
                "downstream_hub": hub_vidpid,
            }
    return None


def record_state(result: Dict, ok: bool, last_action: str):
    state = load_state()
    state["last_attempt_time"] = result.get("time", now_str())
    state["last_action"] = last_action
    state["last_result_ok"] = bool(ok)
    if ok:
        state["last_success_time"] = result.get("time", now_str())
    if result.get("powercycle_done"):
        state["last_powercycle_time"] = result.get("time", now_str())
    state["last_devices_found"] = result.get("devices_found", [])
    state["last_devices_targeted"] = result.get("devices_targeted", [])
    save_state(state)


def check_rate_limit(min_interval_minutes: int = 60) -> Optional[Tuple[str, int]]:
    """
    Check if a power cycle was done within the last min_interval_minutes.
    Returns None if OK to proceed, or (last_cycle_time, minutes_to_wait) if rate limited.
    """
    state = load_state()
    last_cycle_time = state.get("last_powercycle_time")
    if not last_cycle_time:
        return None  # No previous cycle, OK to proceed
    
    try:
        last_time = datetime.strptime(last_cycle_time, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        elapsed = (now - last_time).total_seconds() / 60  # minutes
        
        if elapsed < min_interval_minutes:
            minutes_to_wait = int(min_interval_minutes - elapsed) + 1  # Round up
            return (last_cycle_time, minutes_to_wait)
    except (ValueError, TypeError):
        # Invalid date format, ignore rate limiting
        pass
    
    return None


def emit(result: Dict, json_output: bool):
    global LAST_RESULT
    LAST_RESULT = result
    if json_output:
        print(json.dumps(result))
    else:
        print(result.get("summary", ""))
        
def match_target_for_power_on(original: Dict, uhubctl_output: str) -> Tuple[Dict, str]:
    """
    Pick hub/port for power ON after a port was powered OFF.

    While a port is OFF, SDRplay devices vanish from lsusb and often from uhubctl
    device lists — so we cannot rebuild targets from lsusb alone. Reuse the stored
    upstream hub/port when a fresh match is not available.
    """
    hub = original["hub"]
    port = original["port"]
    mode = original.get("mode", "unknown")

    if mode == "hub_fallback" and original.get("downstream_hub"):
        up = find_upstream_port_for_downstream_hub(uhubctl_output, original["downstream_hub"])
        if up:
            return up, (
                f"re-matched hub_fallback downstream {original['downstream_hub']} "
                f"-> hub {up['hub']} port {up['port']}"
            )

    for cand in parse_uhubctl_devices(uhubctl_output):
        if cand["hub"] == hub and cand["port"] == port:
            return cand, f"re-matched direct_sdrplay at hub {hub} port {port}"
        if original.get("serial") and cand.get("serial") == original.get("serial"):
            return cand, f"re-matched direct_sdrplay serial {original['serial']}"

    return dict(original), (
        f"using stored hub {hub} port {port} "
        f"(SDR not visible on bus while port is OFF)"
    )

def main():
    parser = argparse.ArgumentParser(description="Recover SDRplay with service restart first, then USB power-cycle fallback")
    parser.add_argument("--serial", default="", help="Target a specific SDRplay serial (if multiple)")
    parser.add_argument("--json-output", action="store_true", help="Print JSON on stdout (for callers)")
    parser.add_argument("--verify", action="store_true", help="Verify after recovery with SoapySDRUtil")
    # Compatibility flags accepted from older callers; service sequencing is now fixed in this script.
    parser.add_argument("--stop-kismet", action="store_true", help="Compatibility no-op")
    parser.add_argument("--stop-sdrplay", action="store_true", help="Compatibility no-op")
    parser.add_argument("--start-sdrplay", action="store_true", help="Compatibility no-op")
    parser.add_argument("--start-kismet", action="store_true", help="Compatibility no-op")
    parser.add_argument("--kismet-service", default=DEFAULT_KISMET_SERVICE)
    parser.add_argument("--sdrplay-service", default=DEFAULT_SDRPLAY_SERVICE)
    parser.add_argument("--sniffle-service", default=DEFAULT_SNIFFLE_SERVICE)
    parser.add_argument(
        "--expect-rtl433",
        type=int,
        default=None,
        help="Override expected rtl_433 count (default: 2 per SDR from lsusb)",
    )
    parser.add_argument(
        "--health-check-sleep",
        type=float,
        default=DEFAULT_HEALTH_CHECK_SLEEP,
        help="Seconds to wait after starting kismet before rtl_433 health check (default 10)",
    )
    parser.add_argument(
        "--sniffle-restart-sleep",
        type=float,
        default=DEFAULT_SNIFFLE_RESTART_SLEEP,
        help="Seconds to wait after sniffle restart before checking active (default 3)",
    )
    parser.add_argument(
        "--systemctl-stop-timeout",
        type=int,
        default=DEFAULT_SYSTEMCTL_STOP_TIMEOUT,
        help="Timeout seconds for systemctl stop (default 90; uses kill if exceeded)",
    )
    parser.add_argument(
        "--systemctl-timeout",
        type=int,
        default=DEFAULT_SYSTEMCTL_TIMEOUT,
        help="Timeout seconds for systemctl start and other actions (default 60)",
    )
    parser.add_argument("--off-sleep", type=float, default=2.0)
    parser.add_argument("--on-sleep", type=float, default=4.0)
    parser.add_argument("--hub-off-sleep", type=float, default=3.0, help="Extra OFF sleep when power-cycling a hub (default 3.0)")
    parser.add_argument("--rate-limit-minutes", type=int, default=60, help="Minimum minutes between power cycles (default 60)")
    parser.add_argument("--skip-rate-limit", action="store_true", help="Skip rate limiting check")
    parser.add_argument("--sleep", default="", help="Compatibility no-op argument")
    parser.add_argument("--force-recovery", action="store_true", help="Force recovery (bypass rate limiting and other blockers)")
    parser.add_argument("--debug", "-v", action="store_true",
                        help="Print verbose, timestamped step-by-step diagnostics to stderr")
    args = parser.parse_args()
    SYSTEMCTL_CFG["stop_timeout"] = args.systemctl_stop_timeout
    SYSTEMCTL_CFG["timeout"] = args.systemctl_timeout

    global DEBUG
    DEBUG = bool(args.debug)
    dbg("Debug mode enabled")
    dbg(f"Args: {vars(args)}")
    dbg(f"Running as uid={os.geteuid()} (sudo prefix {'NOT ' if os.geteuid() == 0 else ''}needed)")

    result = {
        "ok": False,
        "time": now_str(),
        "actions": [],
        "devices_found": [],
        "devices_targeted": [],
        "summary": "",
        "state_file": STATE_FILE,
        "powercycle_done": False,
        "tpms_restarted": False,
        "wifi_restarted": False,
    }

    # ------------------------------------------------------------------
    # THREE SEPARATE tracks: Sniffle | TPMS (rtl_433/SDR) | WiFi
    # Only restart a track when that track's health check fails.
    # ------------------------------------------------------------------

    # --- 1) Bluetooth / Sniffle (own unit; never restarts kismet) ---
    sniffle_ok, sniffle_detail = ensure_sniffle_active(
        args.sniffle_service, result["actions"], args.sniffle_restart_sleep
    )
    result["sniffle_ok"] = bool(sniffle_ok)
    result["sniffle_detail"] = sniffle_detail
    result["actions"].append(f"Sniffle: {sniffle_detail}")
    print(f"Sniffle: {'OK' if sniffle_ok else 'FAILED'} — {sniffle_detail}", flush=True)

    sdr_count = count_sdrplay_devices()
    expect_rtl433 = expected_rtl433_count(sdr_count, args.expect_rtl433)
    result["sdr_count"] = sdr_count
    result["expect_rtl433"] = expect_rtl433
    result["actions"].append(
        f"SDRplay count via lsusb: {sdr_count} -> expect rtl_433 >= {expect_rtl433} "
        f"({RTL433_PER_SDR} per SDR)"
    )

    serial = args.serial.strip() or None

    # --- 2) Observe TPMS (no restart yet) ---
    dbg("----- TPMS observe (no restart unless unhealthy) -----")
    kismet_ok, rtl_count, health_detail = get_kismet_state_and_rtl433_count(args.kismet_service)
    tpms_ok = bool(kismet_ok and rtl_count >= expect_rtl433)
    result["actions"].append(f"TPMS observe: {health_detail} (expected >= {expect_rtl433})")
    print(
        f"TPMS: {'OK' if tpms_ok else 'BAD'} — {health_detail} "
        f"(need >= {expect_rtl433} rtl_433)",
        flush=True,
    )

    # --- 3) Observe WiFi (no restart yet) ---
    wifi_ok, wifi_detail = wifi_capture_running(args.kismet_service)
    result["wifi_ok"] = bool(wifi_ok)
    result["actions"].append(f"WiFi observe: {wifi_detail}")
    print(f"WiFi: {'OK' if wifi_ok else 'BAD'} — {wifi_detail}", flush=True)

    # --- Fast path: all good → leave kismet/sdrplay alone ---
    if tpms_ok and wifi_ok:
        result["ok"] = True
        result["summary"] = (
            f"Already healthy: no service restart. kismet active, "
            f"rtl_433={rtl_count} (expected >= {expect_rtl433}, {sdr_count} SDR(s)); "
            f"wifi OK; sniffle={'OK' if sniffle_ok else 'FAILED'}"
        )
        result["actions"].append("Skip TPMS/WiFi recovery: both already healthy")
        record_state(result, ok=True, last_action=result["summary"])
        emit(result, args.json_output)
        return 0

    # --- 4) TPMS recovery only when broken (Phase 1 service bounce) ---
    if not tpms_ok:
        dbg("----- TPMS Phase 1: service restart (only because TPMS unhealthy) -----")
        result["actions"].append(
            f"TPMS unhealthy ({health_detail}); restarting sdrplay+kismet"
        )
        result["tpms_restarted"] = True
        ok, msg = systemctl("stop", args.sdrplay_service)
        dbg(f"stop sdrplay ok={ok}: {msg}")
        result["actions"].append(msg)
        ok, msg = systemctl("stop", args.kismet_service)
        dbg(f"stop kismet ok={ok}: {msg}")
        result["actions"].append(msg)
        sleep_dbg(10, "settle after stopping services")
        ok, msg = systemctl("start", args.sdrplay_service)
        dbg(f"start sdrplay ok={ok}: {msg}")
        result["actions"].append(msg)
        ok, msg = start_kismet(args.kismet_service, result["actions"])
        dbg(f"start kismet ok={ok}: {msg}")
        result["actions"].append(msg)

        kismet_ok, rtl_count, health_detail = health_check_kismet(
            args.kismet_service, expect_rtl433, args.health_check_sleep
        )
        tpms_ok = bool(kismet_ok and rtl_count >= expect_rtl433)
        dbg(f"TPMS after Phase 1: ok={tpms_ok} rtl_433={rtl_count}/{expect_rtl433}")
        result["actions"].append(f"TPMS after service restart: {health_detail}")
        if not tpms_ok:
            diagnose_kismet_failure(args.kismet_service, result["actions"])
        else:
            result["actions"].append("TPMS recovered by service restart only")
            # WiFi may have come back with kismet — re-observe
            wifi_ok, wifi_detail = wifi_capture_running(args.kismet_service)
            result["wifi_ok"] = bool(wifi_ok)
            result["actions"].append(f"WiFi after TPMS restart: {wifi_detail}")

    # --- 5) USB power-cycle only if TPMS still broken ---
    if not tpms_ok:
        result["actions"].append(
            f"TPMS still bad after service restart: rtl_433={rtl_count}/{expect_rtl433}. "
            "Proceeding to USB reset flow."
        )

        force_recovery = bool(args.force_recovery or args.skip_rate_limit)

        if not force_recovery:
            rate_limit_check = check_rate_limit(args.rate_limit_minutes)
            if rate_limit_check:
                last_time, minutes_to_wait = rate_limit_check
                # WiFi-only recovery can still run after this block via fall-through... 
                # but we return here for rate limit like before.
                wifi_ok, wifi_detail = wifi_capture_running(args.kismet_service)
                if not wifi_ok:
                    wifi_ok, wifi_detail = ensure_wifi_capture(
                        args.kismet_service, result["actions"], args.health_check_sleep
                    )
                    result["wifi_restarted"] = True
                result["wifi_ok"] = bool(wifi_ok)
                side = format_side_health(
                    result.get("sniffle_ok"),
                    str(result.get("sniffle_detail") or ""),
                    result.get("wifi_ok"),
                )
                result["summary"] = (
                    f"TPMS not recovered by service restart; USB reset rate limited. "
                    f"Last power cycle was at {last_time}. Please wait {minutes_to_wait} more minute(s), "
                    f"or run with --force-recovery."
                    + (f" Side checks: {side}." if side else "")
                )
                result["rate_limited"] = True
                result["last_cycle_time"] = last_time
                result["minutes_to_wait"] = minutes_to_wait
                record_state(result, ok=False, last_action="rate limited")
                emit(result, args.json_output)
                return 9
        else:
            result["actions"].append("Rate limit bypassed via --force-recovery/--skip-rate-limit")

        if not shutil_which("uhubctl"):
            result["summary"] = "uhubctl not found"
            emit(result, args.json_output)
            return 2

        rc, out, err = run_cmd(privileged_cmd("uhubctl"), timeout=30)
        if rc != 0:
            result["summary"] = f"uhubctl failed: {_systemctl_output_text(out, err)}"
            emit(result, args.json_output)
            return 3

        dbg("----- TPMS Phase 2: USB power-cycle -----")
        result["actions"].append("Phase 2: Stop sdrplay and kismet before USB reset")
        ok, msg = systemctl("stop", args.sdrplay_service)
        result["actions"].append(msg)
        ok, msg = systemctl("stop", args.kismet_service)
        result["actions"].append(msg)

        result["devices_found"] = parse_uhubctl_devices(out)
        result["actions"].append("Resolving USB reset target(s) per SDR (lsusb + uhubctl/sysfs)")
        target, target_log = build_reset_targets(out, serial_filter=serial)
        result["actions"].extend(target_log)

        if serial and not target:
            result["summary"] = f"Specified serial not found or not targetable: {serial}"
            record_state(result, ok=False, last_action=result["summary"])
            emit(result, args.json_output)
            return 5

        if not target:
            result["summary"] = "No USB reset target(s) resolved for SDRplay device(s)"
            record_state(result, ok=False, last_action=result["summary"])
            emit(result, args.json_output)
            return 4

        result["devices_targeted"] = target
        sdr_count = count_sdrplay_devices()
        expect_rtl433 = expected_rtl433_count(sdr_count, args.expect_rtl433)
        result["sdr_count"] = sdr_count
        result["expect_rtl433"] = expect_rtl433

        for d in target:
            hub = d["hub"]
            port = d["port"]
            mode = d.get("mode", "unknown")
            if mode == "hub_fallback":
                result["actions"].append(
                    f"Power-cycling upstream port for downstream hub {d.get('downstream_hub')} "
                    f"(hub {hub} port {port})"
                )
                off_sleep = args.hub_off_sleep
            else:
                result["actions"].append(
                    f"Power-cycling SDRplay port directly (hub {hub} port {port})"
                )
                off_sleep = args.off_sleep

            dbg(f"POWER OFF hub {hub} port {port} (mode={mode})")
            ok, msg = uhubctl_power(hub, port, "off", timeout=20)
            result["actions"].append(f"hub {hub} port {port} off: {msg}")
            if not ok:
                result["summary"] = f"Failed power off hub {hub} port {port}"
                record_state(result, ok=False, last_action=result["summary"])
                emit(result, args.json_output)
                return 6

            sleep_dbg(off_sleep, "port off settle")

            rc_uh, uh_out, uh_err = run_cmd(privileged_cmd("uhubctl"), timeout=30)
            if rc_uh != 0:
                result["summary"] = (
                    f"uhubctl failed before power ON: {uh_err.strip() or uh_out.strip()}"
                )
                record_state(result, ok=False, last_action=result["summary"])
                emit(result, args.json_output)
                return 7

            t2, match_msg = match_target_for_power_on(d, uh_out)
            result["actions"].append(f"Power ON target: {match_msg}")

            dbg(f"POWER ON hub {t2['hub']} port {t2['port']}")
            ok, msg = uhubctl_power(t2["hub"], t2["port"], "on", timeout=20)
            result["actions"].append(f"hub {t2['hub']} port {t2['port']} on: {msg}")
            if not ok:
                result["summary"] = f"Failed power on hub {t2['hub']} port {t2['port']}"
                record_state(result, ok=False, last_action=result["summary"])
                emit(result, args.json_output)
                return 7

            sleep_dbg(args.on_sleep, "port on settle")

        result["powercycle_done"] = True

        dbg("----- POST-RESET: restart services -----")
        result["actions"].append("Post-reset sequence: sleep 10s before restarting services")
        sleep_dbg(10, "pre-start settle after USB reset")
        ok, msg = systemctl("start", args.sdrplay_service)
        dbg(f"start sdrplay ok={ok}: {msg}")
        result["actions"].append(msg)
        sleep_dbg(5, "let sdrplay API come up before kismet")
        ok, msg = start_kismet(args.kismet_service, result["actions"])
        dbg(f"start kismet ok={ok}: {msg}")
        result["actions"].append(msg)

        kismet_ok, rtl_count, health_detail = health_check_kismet(
            args.kismet_service, expect_rtl433, args.health_check_sleep
        )
        tpms_ok = bool(kismet_ok and rtl_count >= expect_rtl433)
        dbg(f"TPMS after USB reset: ok={tpms_ok} rtl={rtl_count}/{expect_rtl433}")
        result["actions"].append(f"Post-reset TPMS health: {health_detail}")
        if not tpms_ok:
            diagnose_kismet_failure(args.kismet_service, result["actions"])
            result["summary"] = (
                f"Reset completed but TPMS health check failed: kismet_ok={kismet_ok}, "
                f"rtl_433={rtl_count}/{expect_rtl433} ({sdr_count} SDR(s) via lsusb)"
            )
            # Still try WiFi track separately below if kismet is up
            wifi_ok, wifi_detail = wifi_capture_running(args.kismet_service)
            if not wifi_ok and kismet_ok:
                wifi_ok, wifi_detail = ensure_wifi_capture(
                    args.kismet_service, result["actions"], args.health_check_sleep
                )
                result["wifi_restarted"] = True
            result["wifi_ok"] = bool(wifi_ok)
            record_state(result, ok=False, last_action=result["summary"])
            emit(result, args.json_output)
            return 10

        if args.verify:
            ok, vmsg = soapy_verify()
            result["actions"].append(vmsg)
            if not ok:
                result["summary"] = vmsg
                record_state(result, ok=False, last_action=vmsg)
                emit(result, args.json_output)
                return 8

        wifi_ok, wifi_detail = wifi_capture_running(args.kismet_service)
        result["wifi_ok"] = bool(wifi_ok)
        result["actions"].append(f"WiFi after USB reset: {wifi_detail}")

        if any(d.get("mode") == "hub_fallback" for d in target):
            uniq = sorted({d.get("downstream_hub") for d in target if d.get("downstream_hub")})
            usb_note = f"Power-cycled upstream port(s) for hub(s) {', '.join(uniq)}"
        else:
            first = target[0]
            usb_note = (
                f"Power-cycled SDRplay port(s), first hub {first['hub']} port {first['port']}"
            )
        # Fall through to WiFi-only fix if still needed, then final summary
        result["actions"].append(f"TPMS recovered after USB: {usb_note}")
        result["_usb_note"] = usb_note

    # --- 6) WiFi recovery only when WiFi still broken (may restart kismet alone) ---
    wifi_ok, wifi_detail = wifi_capture_running(args.kismet_service)
    if not wifi_ok:
        dbg("----- WiFi-only recovery (kismet restart if capture missing) -----")
        result["actions"].append(f"WiFi unhealthy ({wifi_detail}); ensuring capture")
        wifi_ok, wifi_detail = ensure_wifi_capture(
            args.kismet_service, result["actions"], args.health_check_sleep
        )
        result["wifi_restarted"] = True
        result["wifi_ok"] = bool(wifi_ok)
        result["actions"].append(f"WiFi after ensure: {wifi_detail}")
        print(f"WiFi after fix: {'OK' if wifi_ok else 'BAD'} — {wifi_detail}", flush=True)

        # Kismet bounce for WiFi must not silently break TPMS; re-observe only.
        kismet_ok2, rtl_count2, health2 = get_kismet_state_and_rtl433_count(args.kismet_service)
        result["actions"].append(f"TPMS re-check after WiFi fix: {health2}")
        tpms_ok = bool(kismet_ok2 and rtl_count2 >= expect_rtl433)
        rtl_count = rtl_count2 if kismet_ok2 else 0
        if not tpms_ok:
            result["actions"].append(
                "TPMS regressed after WiFi-only kismet restart; running TPMS service restart once"
            )
            result["tpms_restarted"] = True
            ok, msg = systemctl("stop", args.sdrplay_service)
            result["actions"].append(msg)
            ok, msg = systemctl("stop", args.kismet_service)
            result["actions"].append(msg)
            sleep_dbg(5, "settle before TPMS recovery after wifi bounce")
            ok, msg = systemctl("start", args.sdrplay_service)
            result["actions"].append(msg)
            ok, msg = start_kismet(args.kismet_service, result["actions"])
            result["actions"].append(msg)
            kismet_ok, rtl_count, health_detail = health_check_kismet(
                args.kismet_service, expect_rtl433, args.health_check_sleep
            )
            tpms_ok = bool(kismet_ok and rtl_count >= expect_rtl433)
            result["actions"].append(f"TPMS after regression recovery: {health_detail}")
            wifi_ok, wifi_detail = wifi_capture_running(args.kismet_service)
            result["wifi_ok"] = bool(wifi_ok)
    else:
        result["wifi_ok"] = True
        result["actions"].append(f"WiFi already healthy: {wifi_detail}")

    # --- Final report ---
    parts = []
    if result.get("tpms_restarted") or result.get("powercycle_done"):
        if result.get("powercycle_done"):
            parts.append(
                f"TPMS recovered after USB ({result.get('_usb_note', 'reset')}); "
                f"rtl_433={rtl_count}"
            )
        else:
            parts.append(f"TPMS recovered by service restart; rtl_433={rtl_count}")
    elif tpms_ok:
        parts.append(f"TPMS already OK (rtl_433={rtl_count}); no TPMS service restart")
    else:
        parts.append(f"TPMS still BAD (rtl_433={rtl_count}/{expect_rtl433})")

    if result.get("wifi_restarted"):
        parts.append(f"wifi={'OK' if wifi_ok else 'MISSING'} after kismet fix")
    else:
        parts.append(f"wifi={'OK' if wifi_ok else 'MISSING'} (no wifi restart)")

    parts.append(f"sniffle={'OK' if sniffle_ok else 'FAILED'}")

    result["ok"] = bool(tpms_ok)
    result["summary"] = "; ".join(parts)
    record_state(result, ok=result["ok"], last_action=result["summary"])
    emit(result, args.json_output)
    return 0 if result["ok"] else 10


if __name__ == "__main__":
    try:
        rc = main()
        dbg(f"main() returned exit code {rc}")
        log_execution(LAST_RESULT, rc)
        sys.exit(rc)
    except Exception as e:
        dbg(f"UNHANDLED EXCEPTION: {type(e).__name__}: {e}")
        err_result = {
            "ok": False,
            "summary": f"Recovery script error: {e}",
            "time": now_str(),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        }
        log_execution(err_result, 1)
        print(json.dumps(err_result))
        sys.exit(1)
