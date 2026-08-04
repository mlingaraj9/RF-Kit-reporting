#!/usr/bin/env python3
"""
Watchdog for SDRplay/Kismet/Sniffle.

Every 60 seconds checks ALL THREE RF tracks:
  - TPMS      : kismet.service active AND rtl_433 count >= expected (2 per SDR, auto-detected)
  - WiFi      : kismet_cap_linux_wifi present in kismet.service cgroup
  - Bluetooth : sniff_receiver present in sniffle.service cgroup

If ANY track is unhealthy, runs sdrplay_recover.py (without --force-recovery, so the
built-in 1-hour power-cycle rate limit applies). The recovery script handles each track
independently and only restarts what is actually broken.

Designed to run as a systemd service (e.g. sdrplay-recovery-watchdog.service).
"""
import os
import sys
import time
import subprocess
import logging
from pathlib import Path

# Run from same directory as this script so we can import sdrplay_recover
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) != os.getcwd():
    os.chdir(SCRIPT_DIR)
    sys.path.insert(0, str(SCRIPT_DIR))

from sdrplay_recover import (
    get_kismet_state_and_rtl433_count,
    wifi_capture_running,
    sniffle_receiver_running,
    count_sdrplay_devices,
    expected_rtl433_count,
    DEFAULT_KISMET_SERVICE,
    DEFAULT_SNIFFLE_SERVICE,
)

CHECK_INTERVAL_SEC = 60
RECOVER_SCRIPT = SCRIPT_DIR / "sdrplay_recover.py"

# Log every healthy check, or only state changes + problems.
# False keeps journald quiet (~2 lines/day instead of ~1440).
VERBOSE_HEALTHY = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def check_all_tracks():
    """
    Returns (healthy, summary, unhealthy_track_names).
    Expected rtl_433 count is derived from how many SDRplay units lsusb sees
    (2 workers per SDR), so a kit that loses one radio is correctly flagged.
    """
    sdr_count = count_sdrplay_devices()
    expect_rtl433 = expected_rtl433_count(sdr_count)

    kismet_ok, rtl_count, tpms_detail = get_kismet_state_and_rtl433_count(DEFAULT_KISMET_SERVICE)
    tpms_ok = bool(kismet_ok and rtl_count >= expect_rtl433)

    wifi_ok, wifi_detail = wifi_capture_running(DEFAULT_KISMET_SERVICE)
    ble_ok, ble_detail = sniffle_receiver_running(DEFAULT_SNIFFLE_SERVICE)

    bad = []
    if not tpms_ok:
        bad.append("TPMS")
    if not wifi_ok:
        bad.append("WiFi")
    if not ble_ok:
        bad.append("BLE")

    summary = (
        f"TPMS={'OK' if tpms_ok else 'BAD'} (rtl_433={rtl_count}/{expect_rtl433}, "
        f"{sdr_count} SDR) | WiFi={'OK' if wifi_ok else 'BAD'} | "
        f"BLE={'OK' if ble_ok else 'BAD'}"
    )
    if bad:
        details = []
        if not tpms_ok:
            details.append(f"TPMS: {tpms_detail}")
        if not wifi_ok:
            details.append(f"WiFi: {wifi_detail}")
        if not ble_ok:
            details.append(f"BLE: {ble_detail}")
        summary += " || " + " ; ".join(details)

    return (not bad), summary, bad


def main():
    if not RECOVER_SCRIPT.is_file():
        log.error("Recovery script not found: %s", RECOVER_SCRIPT)
        sys.exit(1)

    log.info(
        "Watchdog started: check every %ds; tracks = TPMS (auto rtl_433 count), WiFi, BLE",
        CHECK_INTERVAL_SEC,
    )

    check_count = 0
    last_healthy = None   # None = unknown at startup

    while True:
        try:
            check_count += 1
            healthy, summary, bad = check_all_tracks()

            if healthy:
                if last_healthy is False:
                    log.info("RECOVERED — all tracks healthy: %s", summary)
                elif VERBOSE_HEALTHY or last_healthy is None:
                    log.info("Check #%d OK: %s", check_count, summary)
                last_healthy = True
            else:
                log.warning(
                    "Check #%d UNHEALTHY [%s]: %s — running recovery (no force)",
                    check_count, ",".join(bad), summary,
                )
                last_healthy = False

                proc = subprocess.run(
                    [sys.executable, str(RECOVER_SCRIPT)],
                    cwd=str(SCRIPT_DIR),
                    timeout=900,
                )
                if proc.returncode == 0:
                    log.info("Recovery completed successfully")
                elif proc.returncode == 9:
                    log.info("Recovery skipped (rate limited); will retry next interval")
                else:
                    log.warning("Recovery exited with code %d", proc.returncode)

        except subprocess.TimeoutExpired:
            log.error("Recovery script timed out")
        except Exception as e:
            log.exception("Watchdog error: %s", e)

        time.sleep(CHECK_INTERVAL_SEC)


if __name__ == "__main__":
    main()