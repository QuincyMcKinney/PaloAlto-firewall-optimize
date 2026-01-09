"""
Standalone PAN-OS Firewall: Disable NAT rules from a CSV (match on "Name" column).

OVERVIEW:

This is a Palo Alto firewall hygiene script that disables unused NAT rules. The script takes inputs from a CSV file generated from the Palo Alto Policy Optimizer tool.  

FEATURES:

Python side:
- User configuration prompts: firewall mgmt IP/hostname, username, password (getpass), CSV path
- Assumes default vsys1
- Reads Policy Optimizer/exports that include a "Name" column
- De-duplicates rule names, strips optional "[Disabled]" prefix
- Console + file logging
- User-configurable rate limiting for WRITE calls (set operations)
- Generates a CSV results report
- Candidate-config only (NO commit)

PAN-OS side:
- Uses pan-os-python SDK only (Firewall + xapi)
- Reads NAT rules from candidate config via XPath:
    /config/devices/entry[@name='<device>']/vsys/entry[@name='vsys1']/rulebase/nat/rules
- Disables by setting <disabled>yes</disabled> on the rule entry

CSV requirements:
- Must contain a header column "Name" (case-insensitive)

Minimum Software Requirements:
- Python 3.9.5
- PAN-OS SDK 1.12.0
- PAN-OS Software Version: 11.X.X
"""

import csv
import getpass
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from panos.firewall import Firewall

VSYS = "vsys1"


# ──────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────
def setup_logging() -> Tuple[logging.Logger, str]:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.abspath(f"disable_firewall_nat_rules_{ts}.log")

    logger = logging.getLogger("firewall_nat_rule_disabler")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    logger.addHandler(sh)
    logger.addHandler(fh)

    logger.info("Logging initialized")
    logger.info("Log file: %s", log_path)
    logger.info("Assuming default firewall vsys: %s", VSYS)
    return logger, log_path


# ──────────────────────────────────────────────────────────────────
# RATE LIMITER (WRITE CALLS ONLY)
# ──────────────────────────────────────────────────────────────────
class WriteRateLimiter:
    """
    Python side: throttles XAPI write calls (set)
    PAN-OS side: helps avoid management-plane CPU spikes
    """

    def __init__(
        self,
        logger: logging.Logger,
        max_writes_before_pause: int,
        pause_seconds: float,
        min_seconds_between_writes: float,
    ):
        self.logger = logger
        self.max_writes_before_pause = max_writes_before_pause
        self.pause_seconds = pause_seconds
        self.min_seconds_between_writes = min_seconds_between_writes
        self.write_count = 0
        self._last_write_ts: Optional[float] = None

    def before_write(self) -> None:
        if self.min_seconds_between_writes and self._last_write_ts is not None:
            elapsed = time.time() - self._last_write_ts
            if elapsed < self.min_seconds_between_writes:
                time.sleep(self.min_seconds_between_writes - elapsed)

        if self.max_writes_before_pause and self.write_count > 0:
            if self.write_count % self.max_writes_before_pause == 0:
                self.logger.info(
                    "Rate limit reached (%d writes). Pausing for %s seconds...",
                    self.write_count,
                    self.pause_seconds,
                )
                time.sleep(self.pause_seconds)

    def after_write(self) -> None:
        self.write_count += 1
        self._last_write_ts = time.time()


def prompt_int(prompt: str, default: int) -> int:
    raw = input(f"{prompt} [{default}]: ").strip()
    return default if raw == "" else int(raw)


def prompt_float(prompt: str, default: float) -> float:
    raw = input(f"{prompt} [{default}]: ").strip()
    return default if raw == "" else float(raw)


# ──────────────────────────────────────────────────────────────────
# CSV INPUT
# ──────────────────────────────────────────────────────────────────
def read_rule_names_from_csv(csv_path: str, logger: logging.Logger) -> List[str]:
    """
    Reads NAT rule names from a CSV column named "Name" (case-insensitive).
    Strips optional '[Disabled]' prefix from some exports.
    """
    if not os.path.isfile(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV appears to have no header row.")

        # Normalize header lookup
        headers = {h.strip().strip('"').strip("'").lower(): h for h in reader.fieldnames}
        name_col = headers.get("name")
        if not name_col:
            raise ValueError(
                "CSV must contain a 'Name' column. "
                f"Found headers: {', '.join(reader.fieldnames)}"
            )

        names: List[str] = []
        for i, row in enumerate(reader, start=2):
            n = (row.get(name_col) or "").strip()
            if not n:
                logger.warning("Skipping CSV line %d: empty Name", i)
                continue

            if n.lower().startswith("[disabled]"):
                n = n[len("[disabled]"):].strip()

            names.append(n)

    # De-dupe preserving order
    deduped = list(dict.fromkeys(names))
    if len(deduped) != len(names):
        logger.info("De-duplicated rule names: %d → %d", len(names), len(deduped))
    return deduped


# ──────────────────────────────────────────────────────────────────
# FIREWALL XPATH HELPERS
# ──────────────────────────────────────────────────────────────────
def discover_device_entry_name(fw: Firewall, logger: logging.Logger) -> str:
    """
    PAN-OS side: find /config/devices/entry[@name='...'] name
    """
    resp = fw.xapi.get(xpath="/config/devices")
    for e in resp.findall(".//entry"):
        name = e.get("name")
        if name:
            logger.info("Discovered firewall device entry name: %s", name)
            return name
    raise RuntimeError("Unable to discover firewall device entry name under /config/devices")


def nat_rules_base_xpath(device_entry: str) -> str:
    """
    Candidate-config NAT rulebase path
    """
    return (
        f"/config/devices/entry[@name='{device_entry}']"
        f"/vsys/entry[@name='{VSYS}']"
        f"/rulebase/nat/rules"
    )


def build_nat_rule_map(fw: Firewall, base_xpath: str, logger: logging.Logger) -> Dict[str, str]:
    """
    Build name -> rule_entry_xpath map from NAT rules in candidate config.
    """
    logger.info("Retrieving NAT rules via XPath: %s", base_xpath)
    resp = fw.xapi.get(xpath=base_xpath)
    entries = resp.findall(".//entry")

    rule_map: Dict[str, str] = {}
    for e in entries:
        rname = e.get("name")
        if rname:
            rule_map[rname] = base_xpath + f"/entry[@name='{rname}']"

    logger.info("Discovered %d NAT rules in candidate config", len(rule_map))
    return rule_map


def is_rule_disabled(fw: Firewall, rule_xpath: str) -> bool:
    resp = fw.xapi.get(xpath=rule_xpath + "/disabled")
    elem = resp.find(".//disabled")
    return elem is not None and (elem.text or "").strip().lower() == "yes"


def disable_rule(fw: Firewall, rule_xpath: str, limiter: WriteRateLimiter) -> None:
    limiter.before_write()
    fw.xapi.set(xpath=rule_xpath, element="<disabled>yes</disabled>")
    limiter.after_write()


# ──────────────────────────────────────────────────────────────────
# CSV REPORT
# ──────────────────────────────────────────────────────────────────
def write_results_csv(rows: List[Dict[str, str]], logger: logging.Logger) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = os.path.abspath(f"firewall_nat_disable_report_{ts}.csv")

    fieldnames = ["rule_name", "status", "notes"]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(
                {
                    "rule_name": r.get("rule_name", ""),
                    "status": r.get("status", ""),
                    "notes": r.get("notes", ""),
                }
            )

    logger.info("CSV report written to: %s", out_path)
    return out_path


# ──────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────
def main() -> None:
    logger, log_path = setup_logging()
    logger.info("=== Standalone Firewall NAT Rule Disabler (Name + Rate Limit + CSV Report) ===")

    # User configuration prompts
    fw_ip = input("Firewall management IP/hostname: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    csv_path = input("CSV file path: ").strip()

    print("\n--- Rate Limiting Configuration (WRITE calls only) ---")
    max_writes = prompt_int("Max writes before pause (0 = disable pause-by-count)", 25)
    pause_seconds = prompt_float("Pause duration in seconds", 5.0)
    min_spacing = prompt_float("Minimum seconds between writes (0 = no spacing)", 0.2)

    logger.info(
        "User rate limits: max_writes=%s, pause_seconds=%s, min_spacing=%s",
        max_writes,
        pause_seconds,
        min_spacing,
    )

    limiter = WriteRateLimiter(
        logger=logger,
        max_writes_before_pause=max_writes,
        pause_seconds=pause_seconds,
        min_seconds_between_writes=min_spacing,
    )

    try:
        rule_names = read_rule_names_from_csv(csv_path, logger)
        logger.info("Loaded %d unique rule names from CSV", len(rule_names))
        if not rule_names:
            logger.warning("No rule names found. Exiting.")
            return

        logger.info("Connecting to firewall %s (vsys=%s)...", fw_ip, VSYS)
        fw = Firewall(hostname=fw_ip, api_username=username, api_password=password, vsys=VSYS)

        device_entry = discover_device_entry_name(fw, logger)
        base_xpath = nat_rules_base_xpath(device_entry)

        rule_map = build_nat_rule_map(fw, base_xpath, logger)

        totals = {"DISABLED": 0, "ALREADY_DISABLED": 0, "NOT_FOUND": 0, "ERROR": 0}
        report_rows: List[Dict[str, str]] = []

        for idx, name in enumerate(rule_names, start=1):
            logger.info("[%d/%d] Processing NAT rule: %s", idx, len(rule_names), name)
            row = {"rule_name": name, "status": "NOT_FOUND", "notes": ""}

            rule_xpath = rule_map.get(name)
            if not rule_xpath:
                totals["NOT_FOUND"] += 1
                row["status"] = "NOT_FOUND"
                logger.warning("NOT_FOUND: %s", name)
                report_rows.append(row)
                continue

            try:
                if is_rule_disabled(fw, rule_xpath):
                    totals["ALREADY_DISABLED"] += 1
                    row["status"] = "ALREADY_DISABLED"
                    logger.info("ALREADY_DISABLED: %s", name)
                else:
                    disable_rule(fw, rule_xpath, limiter)
                    totals["DISABLED"] += 1
                    row["status"] = "DISABLED"
                    logger.info("DISABLED: %s", name)

            except Exception as e:
                totals["ERROR"] += 1
                row["status"] = "ERROR"
                row["notes"] = str(e)
                logger.exception("ERROR disabling '%s': %s", name, e)

            report_rows.append(row)

        report_path = write_results_csv(report_rows, logger)

        logger.info("=== Summary ===")
        logger.info("Disabled:         %d", totals["DISABLED"])
        logger.info("Already disabled: %d", totals["ALREADY_DISABLED"])
        logger.info("Not found:        %d", totals["NOT_FOUND"])
        logger.info("Errors:           %d", totals["ERROR"])
        logger.info("Write calls made: %d", limiter.write_count)
        logger.info("CSV report: %s", report_path)
        logger.info("Log file:  %s", log_path)

    except Exception as e:
        logger.exception("Unhandled exception: %s", e)
        logger.error("Exiting. Log file: %s", log_path)
        sys.exit(2)


if __name__ == "__main__":
    main()
