#!/usr/bin/env python3
"""
OVERVIEW:

This cleanup tool finds address objects and groups that are not attached to any policy on a Palo Alto firewall.
First, the tool generates a CSV report of the found objects/groups. Then it waits for user confirmation on whether to proceed 
with the deletion process. If the tool is prompted to proceed, it will delete the objects from the candidate 
configuration. After review, commits to the running configuration can be made from the GUI. Once the script is done, 
it will generate a log file for any possible errors.



FEATURES:

Python side:
- Prompts for firewall mgmt IP/hostname, username, password (getpass)
- Prompts for user-driven rate limiting (WRITE calls only)
- Pulls Address Objects + Address Groups from candidate config
- Pulls the vsys rulebase subtree from candidate config and collects <member> references
- Determines which objects/groups are referenced by policies, including nested groups (multi-level)
- Generates a CSV report of unattached objects/groups (includes description + group members)
- Waits for user confirmation ("DELETE") before deleting anything
- Deletes nested groups safely (outermost → innermost) with retries
- Deletes objects after groups
- Generates an AFTER deletion CSV report listing anything that failed to delete and why
- Logs progress to console and to a timestamped log file

PAN-OS side:
- Uses pan-os-python SDK only (Firewall + xapi)
- Reads config via XPath GET (candidate config)
- Deletes config via XPath DELETE (candidate config)
- NO commit is performed

ASSUMPTIONS / SCOPE:

- Standalone firewall (NOT Panorama)
- Default vsys: vsys1

MINUMUM SOFTWARE:
- Python 3.9.5
- PAN-OS SDK 1.12.0
- PAN-OS Software Version: 11.X.X
"""

import csv
import getpass
import logging
import os
import re
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from panos.firewall import Firewall

VSYS = "vsys1"


# ──────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────
def setup_logging() -> Tuple[logging.Logger, str]:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.abspath(f"unattached_addr_cleanup_{ts}.log")

    logger = logging.getLogger("unattached_addr_cleanup")
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
    logger.info("Assuming firewall vsys: %s", VSYS)
    return logger, log_path


# ──────────────────────────────────────────────────────────────────
# RATE LIMITER (WRITE CALLS ONLY)
# ──────────────────────────────────────────────────────────────────
class WriteRateLimiter:
    """
    Python side:
    - Controls frequency of XAPI write calls (DELETE operations)

    PAN-OS side:
    - Reduces bursty config writes to avoid management plane CPU spikes
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
        # Minimum spacing between writes
        if self.min_seconds_between_writes and self._last_write_ts is not None:
            elapsed = time.time() - self._last_write_ts
            if elapsed < self.min_seconds_between_writes:
                time.sleep(self.min_seconds_between_writes - elapsed)

        # Pause after N writes
        if self.max_writes_before_pause and self.write_count > 0:
            if self.write_count % self.max_writes_before_pause == 0:
                self.logger.info(
                    "Rate limit: %d writes reached, pausing for %s seconds...",
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
# PAN-OS XPATH HELPERS
# ──────────────────────────────────────────────────────────────────
def discover_device_entry_name(fw: Firewall, logger: logging.Logger) -> str:
    """
    PAN-OS config root includes /config/devices/entry[@name='<DEVICE_ENTRY>']...
    We discover it dynamically for portability.
    """
    resp = fw.xapi.get(xpath="/config/devices")
    for e in resp.findall(".//entry"):
        name = e.get("name")
        if name:
            logger.info("Discovered device entry name: %s", name)
            return name
    raise RuntimeError("Unable to discover device entry name under /config/devices")


def vsys_address_xpath(device_entry: str) -> str:
    return (
        f"/config/devices/entry[@name='{device_entry}']"
        f"/vsys/entry[@name='{VSYS}']"
        f"/address"
    )


def vsys_address_group_xpath(device_entry: str) -> str:
    return (
        f"/config/devices/entry[@name='{device_entry}']"
        f"/vsys/entry[@name='{VSYS}']"
        f"/address-group"
    )


def vsys_rulebase_xpath(device_entry: str) -> str:
    return (
        f"/config/devices/entry[@name='{device_entry}']"
        f"/vsys/entry[@name='{VSYS}']"
        f"/rulebase"
    )


# ──────────────────────────────────────────────────────────────────
# CONFIG DISCOVERY
# ──────────────────────────────────────────────────────────────────
def _get_description(entry_elem) -> str:
    d = entry_elem.find("./description")
    if d is not None and d.text:
        return d.text.strip()
    return ""


def load_address_objects(
    fw: Firewall, addr_xpath: str, logger: logging.Logger
) -> Tuple[Set[str], Dict[str, str]]:
    """
    Returns:
      - set of address object names
      - dict name -> description
    """
    logger.info("Pulling address objects via XPath: %s", addr_xpath)
    resp = fw.xapi.get(xpath=addr_xpath)

    names: Set[str] = set()
    desc_map: Dict[str, str] = {}

    for e in resp.findall(".//entry"):
        n = e.get("name")
        if not n:
            continue
        names.add(n)
        desc_map[n] = _get_description(e)

    logger.info("Found %d address objects.", len(names))
    return names, desc_map


def load_address_groups(
    fw: Firewall, ag_xpath: str, logger: logging.Logger
) -> Tuple[Set[str], Dict[str, List[str]], Dict[str, str]]:
    """
    Returns:
      - set of group names
      - dict group_name -> list of members (addresses and/or groups)
      - dict group_name -> description
    """
    logger.info("Pulling address groups via XPath: %s", ag_xpath)
    resp = fw.xapi.get(xpath=ag_xpath)

    group_names: Set[str] = set()
    members_map: Dict[str, List[str]] = {}
    desc_map: Dict[str, str] = {}

    for e in resp.findall(".//entry"):
        gname = e.get("name")
        if not gname:
            continue

        group_names.add(gname)
        desc_map[gname] = _get_description(e)

        members = [m.text.strip() for m in e.findall(".//member") if m.text and m.text.strip()]
        members_map[gname] = members

    logger.info("Found %d address groups.", len(group_names))
    return group_names, members_map, desc_map


def collect_policy_members(fw: Firewall, rb_xpath: str, logger: logging.Logger) -> Set[str]:
    """
    Pull the vsys rulebase subtree and collect all <member> values.
    We filter against known address/group names later.
    """
    logger.info("Pulling rulebase subtree via XPath: %s", rb_xpath)
    resp = fw.xapi.get(xpath=rb_xpath)

    members: Set[str] = set()
    for m in resp.findall(".//member"):
        if m.text and m.text.strip():
            members.add(m.text.strip())

    logger.info("Collected %d unique <member> values from rulebase.", len(members))
    return members


# ──────────────────────────────────────────────────────────────────
# USED/UNUSED CALCULATION
# ──────────────────────────────────────────────────────────────────
def compute_used_sets(
    all_addresses: Set[str],
    all_groups: Set[str],
    group_members: Dict[str, List[str]],
    policy_members: Set[str],
    logger: logging.Logger,
) -> Tuple[Set[str], Set[str]]:
    """
    An address object is "used" if:
      - referenced directly by policy, OR
      - part of a group that is used (including nested groups)

    A group is "used" if:
      - referenced directly by policy, OR
      - nested inside another used group
    """
    used_addresses: Set[str] = set(m for m in policy_members if m in all_addresses)
    used_groups: Set[str] = set(m for m in policy_members if m in all_groups)

    logger.info("Directly referenced in policy: %d addresses, %d groups.", len(used_addresses), len(used_groups))

    stack = list(used_groups)
    visited_groups: Set[str] = set()

    while stack:
        g = stack.pop()
        if g in visited_groups:
            continue
        visited_groups.add(g)

        for member in group_members.get(g, []):
            if member in all_addresses:
                used_addresses.add(member)
            elif member in all_groups:
                if member not in used_groups:
                    used_groups.add(member)
                stack.append(member)

    logger.info(
        "After recursive group expansion: %d used addresses, %d used groups.",
        len(used_addresses),
        len(used_groups),
    )
    return used_addresses, used_groups


# ──────────────────────────────────────────────────────────────────
# REPORTING (PRE-DELETE)
# ──────────────────────────────────────────────────────────────────
def write_unattached_report_csv(
    device_ip: str,
    unattached_addresses: Set[str],
    unattached_groups: Set[str],
    group_members: Dict[str, List[str]],
    addr_desc: Dict[str, str],
    group_desc: Dict[str, str],
    logger: logging.Logger,
) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = os.path.abspath(f"unattached_objects_report_{device_ip}_{ts}.csv")

    fieldnames = ["object_type", "name", "description", "members", "scope", "notes"]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()

        for g in sorted(unattached_groups):
            w.writerow(
                {
                    "object_type": "address-group",
                    "name": g,
                    "description": group_desc.get(g, ""),
                    "members": ";".join(group_members.get(g, [])),
                    "scope": f"vsys:{VSYS}",
                    "notes": "Not referenced by any policy (directly or via used groups)",
                }
            )

        for a in sorted(unattached_addresses):
            w.writerow(
                {
                    "object_type": "address",
                    "name": a,
                    "description": addr_desc.get(a, ""),
                    "members": "",
                    "scope": f"vsys:{VSYS}",
                    "notes": "Not referenced by any policy (directly or via used groups)",
                }
            )

    logger.info("Unattached objects report written to: %s", out_path)
    return out_path


# ──────────────────────────────────────────────────────────────────
# GROUP DELETION ORDER
# ──────────────────────────────────────────────────────────────────
def _extract_nested_group_edges(
    groups_to_delete: Set[str],
    group_members: Dict[str, List[str]],
) -> Dict[str, Set[str]]:
    """
    Build adjacency list of parent -> child, but only when BOTH parent and child
    are in groups_to_delete.
    """
    edges: Dict[str, Set[str]] = {g: set() for g in groups_to_delete}
    for parent in groups_to_delete:
        for member in group_members.get(parent, []):
            if member in groups_to_delete:
                edges[parent].add(member)
    return edges


def compute_group_deletion_order(
    groups_to_delete: Set[str],
    group_members: Dict[str, List[str]],
    logger: logging.Logger,
) -> List[str]:
    """
    If parent contains child, parent must be deleted BEFORE child.

    We compute a topological order where in_degree[child] counts how many parents
    reference that child (within the delete-set). Groups with in_degree==0 are
    safe to delete first (outermost).
    """
    edges = _extract_nested_group_edges(groups_to_delete, group_members)

    in_degree: Dict[str, int] = {g: 0 for g in groups_to_delete}
    for parent, children in edges.items():
        for child in children:
            in_degree[child] += 1

    queue = [g for g, deg in in_degree.items() if deg == 0]
    queue.sort()

    order: List[str] = []
    while queue:
        g = queue.pop(0)
        order.append(g)

        for child in edges.get(g, set()):
            in_degree[child] -= 1
            if in_degree[child] == 0:
                queue.append(child)
                queue.sort()

    remaining = [g for g in groups_to_delete if g not in order]
    if remaining:
        logger.warning(
            "Detected %d group(s) with unresolved nesting (possible cycle). "
            "They will be attempted after the ordered deletes.",
            len(remaining),
        )
        remaining.sort()
        order.extend(remaining)

    return order


# ──────────────────────────────────────────────────────────────────
# AFTER-DELETION REPORTING
# ──────────────────────────────────────────────────────────────────
def extract_reference_path(err: Exception) -> str:
    """
    Extract the 'references from:' chain from PanXapiError text when present.
    """
    msg = str(err).replace("\r\n", "\n").replace("\r", "\n")
    m = re.search(r"references from:\s*(.+)$", msg, flags=re.IGNORECASE | re.DOTALL)
    if m:
        ref = m.group(1).strip()
        ref = " | ".join([line.strip() for line in ref.split("\n") if line.strip()])
        return ref
    return ""


def write_after_deletion_report_csv(
    device_ip: str,
    failures: List[Dict[str, str]],
    logger: logging.Logger,
) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = os.path.abspath(f"post_delete_failures_{device_ip}_{ts}.csv")

    fieldnames = ["object_type", "name", "attempted_xpath", "error", "reference_path"]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in failures:
            w.writerow({k: row.get(k, "") for k in fieldnames})

    logger.info("After-deletion failure report written to: %s", out_path)
    return out_path


# ──────────────────────────────────────────────────────────────────
# DELETION (CANDIDATE CONFIG ONLY)
# ──────────────────────────────────────────────────────────────────
def delete_xpath(fw: Firewall, xpath: str, limiter: WriteRateLimiter) -> None:
    limiter.before_write()
    fw.xapi.delete(xpath=xpath)
    limiter.after_write()


def delete_unattached_objects(
    fw: Firewall,
    device_entry: str,
    unattached_groups: Set[str],
    unattached_addresses: Set[str],
    group_members: Dict[str, List[str]],
    limiter: WriteRateLimiter,
    logger: logging.Logger,
    device_ip_for_reports: str,
) -> Tuple[Dict[str, int], str]:
    """
    Deletes unattached groups and addresses from candidate config and writes
    an AFTER deletion report of failures.

    Returns:
      totals dict
      after_report_path
    """
    totals = {"GROUP_DELETED": 0, "ADDR_DELETED": 0, "DELETE_ERRORS": 0}
    failures: List[Dict[str, str]] = []

    ag_base = vsys_address_group_xpath(device_entry)
    a_base = vsys_address_xpath(device_entry)

    # 1) Compute safe group deletion order (outermost -> innermost)
    group_delete_order = compute_group_deletion_order(unattached_groups, group_members, logger)
    logger.info("Planned group deletion order (outer -> inner): %d groups", len(group_delete_order))

    # 2) Delete groups in passes with retries
    pending = list(group_delete_order)
    max_passes = max(2, len(pending))
    logger.info("Deleting address-groups (candidate config) with up to %d passes...", max_passes)

    for pass_num in range(1, max_passes + 1):
        if not pending:
            break

        logger.info("Group delete pass %d: %d group(s) pending", pass_num, len(pending))
        next_pending: List[str] = []
        progress_this_pass = 0

        for g in pending:
            xpath = f"{ag_base}/entry[@name='{g}']"
            try:
                logger.info("DELETE group: %s", g)
                delete_xpath(fw, xpath, limiter)
                totals["GROUP_DELETED"] += 1
                progress_this_pass += 1
            except Exception as e:
                totals["DELETE_ERRORS"] += 1
                next_pending.append(g)
                logger.warning("Could not delete group '%s' this pass (will retry): %s", g, e)
                failures.append(
                    {
                        "object_type": "address-group",
                        "name": g,
                        "attempted_xpath": xpath,
                        "error": str(e),
                        "reference_path": extract_reference_path(e),
                    }
                )

        if progress_this_pass == 0:
            logger.warning(
                "No group deletions succeeded in pass %d. Remaining %d group(s) may have external references.",
                pass_num, len(next_pending)
            )
            pending = next_pending
            break

        pending = next_pending

    # Remove stale group failures for groups that eventually deleted successfully
    deleted_groups = set(group_delete_order) - set(pending)
    if deleted_groups:
        failures = [
            f for f in failures
            if not (f.get("object_type") == "address-group" and f.get("name") in deleted_groups)
        ]

    if pending:
        logger.warning("Groups still not deleted after retries: %d", len(pending))

    # 3) Delete address objects AFTER groups
    logger.info("Deleting %d unattached address objects (candidate config)...", len(unattached_addresses))
    for a in sorted(unattached_addresses):
        xpath = f"{a_base}/entry[@name='{a}']"
        try:
            logger.info("DELETE address: %s", a)
            delete_xpath(fw, xpath, limiter)
            totals["ADDR_DELETED"] += 1
        except Exception as e:
            totals["DELETE_ERRORS"] += 1
            logger.exception("Failed to delete address '%s': %s", a, e)
            failures.append(
                {
                    "object_type": "address",
                    "name": a,
                    "attempted_xpath": xpath,
                    "error": str(e),
                    "reference_path": extract_reference_path(e),
                }
            )

    # 4) Write AFTER deletion report
    after_report = write_after_deletion_report_csv(
        device_ip=device_ip_for_reports,
        failures=failures,
        logger=logger,
    )

    return totals, after_report


# ──────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────
def main() -> None:
    logger, log_path = setup_logging()
    logger.info("=== Standalone Firewall Unattached Address/Group Finder + Optional Deleter ===")

    # USER CONFIGURATION
    fw_ip = input("Firewall management IP/hostname: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    print("\n--- Rate Limiting Configuration (WRITE calls only: deletes) ---")
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

    device_ip_for_reports = fw_ip.replace(":", "_")

    try:
        # Connect to firewall
        logger.info("Connecting to firewall %s (vsys=%s)...", fw_ip, VSYS)
        fw = Firewall(hostname=fw_ip, api_username=username, api_password=password, vsys=VSYS)

        # Discover config roots
        device_entry = discover_device_entry_name(fw, logger)

        addr_xpath = vsys_address_xpath(device_entry)
        ag_xpath = vsys_address_group_xpath(device_entry)
        rb_xpath = vsys_rulebase_xpath(device_entry)

        # Pull objects/groups + descriptions
        all_addresses, addr_desc = load_address_objects(fw, addr_xpath, logger)
        all_groups, group_members, group_desc = load_address_groups(fw, ag_xpath, logger)

        # Pull policy references
        policy_members = collect_policy_members(fw, rb_xpath, logger)

        # Compute "used"
        used_addresses, used_groups = compute_used_sets(
            all_addresses=all_addresses,
            all_groups=all_groups,
            group_members=group_members,
            policy_members=policy_members,
            logger=logger,
        )

        # Anything not used is "unattached" (including nested group members)
        unattached_addresses = all_addresses - used_addresses
        unattached_groups = all_groups - used_groups

        logger.info("Unattached addresses: %d", len(unattached_addresses))
        logger.info("Unattached groups:    %d", len(unattached_groups))

        # Generate report CSV (always)
        report_path = write_unattached_report_csv(
            device_ip=device_ip_for_reports,
            unattached_addresses=unattached_addresses,
            unattached_groups=unattached_groups,
            group_members=group_members,
            addr_desc=addr_desc,
            group_desc=group_desc,
            logger=logger,
        )

        # If nothing to delete, stop
        if not unattached_addresses and not unattached_groups:
            logger.info("No unattached objects/groups found. Nothing to delete.")
            logger.info("Pre-delete report: %s", report_path)
            logger.info("Log: %s", log_path)
            return

        # Confirmation gate
        print("\n============================================================")
        print("PRE-DELETE REPORT GENERATED")
        print(f"  Unattached report: {report_path}")
        print("============================================================")
        print("Next step: delete the unattached objects/groups from CANDIDATE config.")
        print("This script WILL NOT commit, but deletions will be staged in candidate config.")
        print("============================================================\n")

        confirm = input("Type 'DELETE' to proceed with deletion, or anything else to exit: ").strip()
        if confirm != "DELETE":
            logger.info("User did not confirm deletion. Exiting without changes.")
            logger.info("Pre-delete report: %s", report_path)
            logger.info("Log: %s", log_path)
            return

        # Delete with nested handling + after deletion report
        totals, after_report_path = delete_unattached_objects(
            fw=fw,
            device_entry=device_entry,
            unattached_groups=unattached_groups,
            unattached_addresses=unattached_addresses,
            group_members=group_members,
            limiter=limiter,
            logger=logger,
            device_ip_for_reports=device_ip_for_reports,
        )

        logger.info("=== Deletion Summary (candidate config only; no commit performed) ===")
        logger.info("Groups deleted:    %d", totals["GROUP_DELETED"])
        logger.info("Addresses deleted: %d", totals["ADDR_DELETED"])
        logger.info("Delete errors:     %d", totals["DELETE_ERRORS"])
        logger.info("Write calls made:  %d", limiter.write_count)
        logger.info("Pre-delete report:  %s", report_path)
        logger.info("After-delete report: %s", after_report_path)
        logger.info("Log:               %s", log_path)

    except Exception as e:
        logger.exception("Unhandled exception: %s", e)
        logger.error("Exiting. Log file: %s", log_path)
        sys.exit(2)


if __name__ == "__main__":
    main()
