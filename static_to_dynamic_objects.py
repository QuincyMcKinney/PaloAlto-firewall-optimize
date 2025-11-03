#!/usr/bin/env python3
"""
Purpose:
  Tag all Address Objects that are (directly or indirectly) members of a STATIC Address Group
  on a standalone PAN-OS firewall. This prepares you to later use a Dynamic Address Group
  that matches on this tag — without modifying/creating any DAGs here.

Operational stance:
  - Strict input validation (no defaults, blanks are errors).
  - Supports nested STATIC Address Groups (recursively walks the tree).
  - Does NOT commit. You must commit manually on the firewall after review.
  - Does NOT create/modify Dynamic Address Groups.

Requirements:
  pip install pan-os-python
"""

import sys
import getpass
from typing import Optional, Set, Dict, Tuple

# PAN-OS Python SDK imports:
# - Firewall: connection object to your device (manages API key/session).
# - AddressObject / AddressGroup / Tag: object models that map to PAN-OS config elements.
# - PanDeviceError: common SDK exception for API/transport/config errors.
from panos.firewall import Firewall
from panos.objects import AddressObject, AddressGroup, Tag
from panos.errors import PanDeviceError


# =========================
# 🔧 User input (strict validation)
# =========================
# These inputs simulate a "parameters" block. We immediately validate to avoid surprises later.

USERNAME = input("Firewall username: ").strip()
if not USERNAME:
    sys.exit("❌ ERROR: Username cannot be blank.")

PASSWORD = getpass.getpass("Firewall password: ")
if not PASSWORD:
    sys.exit("❌ ERROR: Password cannot be blank.")

FIREWALL_IP = input("Firewall management IP / FQDN: ").strip()
if not FIREWALL_IP:
    sys.exit("❌ ERROR: Firewall management IP cannot be blank.")

TARGET_STATIC_GROUP = input("Target STATIC Address Group name: ").strip()
if not TARGET_STATIC_GROUP:
    sys.exit("❌ ERROR: Address Group name cannot be blank.")

DYNAMIC_MATCH_TAG = input("Tag to apply to Address Objects: ").strip()
if not DYNAMIC_MATCH_TAG:
    sys.exit("❌ ERROR: Tag name cannot be blank.")


# =========================
# Helper functions
# =========================
def connect_firewall() -> Firewall:
    """
    Connect to the firewall using credentials provided above.

    Python side:
      - Creates a Firewall object (session manager). No API call is sent yet.
      - Actual API interaction happens on the first SDK operation (e.g., refreshall, create, apply).

    PAN-OS side:
      - On first operation, the SDK authenticates and obtains/uses an API key.
    """
    try:
        fw = Firewall(hostname=FIREWALL_IP, api_username=USERNAME, api_password=PASSWORD)
        return fw
    except Exception as e:
        # Any connection/auth issues thrown by the SDK will be explained here.
        sys.exit(f"❌ ERROR: Failed to connect to firewall: {e}")


def load_maps(fw: Firewall) -> Tuple[Dict[str, AddressObject], Dict[str, AddressGroup]]:
    """
    Download all Address Objects and Address Groups from the firewall into Python dictionaries.

    Python side:
      - AddressObject.refreshall(fw) pulls the current config for objects in scope.
      - AddressGroup.refreshall(fw) pulls the current config for groups in scope.
      - We store them as {name: object} for fast lookups by name.

    PAN-OS side:
      - SDK performs "show/config" style API calls to read objects and groups.
      - No configuration is changed on the device by 'refreshall'.
    """
    objs = AddressObject.refreshall(fw, add=False) or []
    groups = AddressGroup.refreshall(fw, add=False) or []
    obj_map = {o.name: o for o in objs}
    grp_map = {g.name: g for g in groups}
    return obj_map, grp_map


def resolve_object_names_from_member(
    member_name: str,
    obj_map: Dict[str, AddressObject],
    grp_map: Dict[str, AddressGroup],
    seen: Optional[Set[str]] = None,
) -> Set[str]:
    """
    Resolve a single group member name into the set of final Address Object names.

    Why this is needed:
      - A STATIC Address Group can contain Address Objects AND/OR other Address Groups.
      - We must recursively walk nested groups until we reach Address Objects.

    Cycle protection:
      - If Group A includes Group B and (by mistake) Group B includes Group A, we avoid looping forever.

    Python side:
      - Uses recursion with a 'seen' set to prevent cycles.
      - Returns a Python set of Address Object NAMES.

    PAN-OS side:
      - This function is pure logic using data already downloaded by refreshall; no API calls here.
    """
    if seen is None:
        seen = set()
    if member_name in seen:
        print(f"⚠️  WARNING: Detected cyclic reference on '{member_name}', skipping.")
        return set()
    seen.add(member_name)

    # Base case: this member is directly an Address Object.
    if member_name in obj_map:
        return {member_name}

    # If not an object, it might be an Address Group (nested).
    g = grp_map.get(member_name)
    if not g:
        print(f"⚠️  WARNING: Member '{member_name}' not found as an AddressObject or AddressGroup.")
        return set()

    # We only recurse into STATIC groups.
    # Dynamic Address Groups are evaluated at runtime by PAN-OS, not expanded in config.
    if g.static_value:
        resolved: Set[str] = set()
        for child in g.static_value:
            resolved |= resolve_object_names_from_member(child, obj_map, grp_map, seen)
        return resolved

    # If it's a dynamic or empty group, there are no static members to convert/tag here.
    print(f"ℹ️  INFO: Member '{member_name}' is a dynamic/empty group; skipping recursion.")
    return set()


def collect_all_address_objects_from_group(
    group: AddressGroup,
    obj_map: Dict[str, AddressObject],
    grp_map: Dict[str, AddressGroup],
) -> Set[str]:
    """
    Expand the TARGET_STATIC_GROUP down to the unique set of Address Object names.

    Python side:
      - Iterates over each direct member of the target group and recursively resolves it.

    PAN-OS side:
      - Still just reading data already in memory; no device changes here.
    """
    all_objs: Set[str] = set()
    for member in group.static_value or []:
        all_objs |= resolve_object_names_from_member(member, obj_map, grp_map, seen=set())
    return all_objs


def ensure_tag(fw: Firewall, tag_name: str) -> Tag:
    """
    Ensure the Tag object exists on the firewall. Create it if missing.

    Python side:
      - Tag.refreshall reads current tags.
      - If the desired tag is absent, we instantiate Tag(name=tag_name), attach it to fw,
        and call .create() to push it into the candidate configuration.

    PAN-OS side:
      - .create() writes the Tag into the candidate config (NOT yet committed).
      - No traffic impact until you commit.
    """
    existing = {t.name: t for t in (Tag.refreshall(fw, add=False) or [])}
    if tag_name in existing:
        return existing[tag_name]
    t = Tag(name=tag_name)
    fw.add(t)     # binds the Tag object into the firewall config tree in the SDK
    t.create()    # pushes creation into candidate config on the device (no commit)
    return t


def tag_objects(
    obj_map: Dict[str, AddressObject],
    object_names: Set[str],
    tag_name: str,
) -> Tuple[int, int]:
    """
    Append the tag to each Address Object (if it's not already present).

    Python side:
      - For each object name, we fetch the AddressObject from obj_map,
        update its .tag list, and call .apply().

    PAN-OS side:
      - .apply() pushes the updated object into the candidate configuration.
      - This does NOT commit; changes remain pending until an admin commits.
    """
    updated = 0
    total = 0
    for name in sorted(object_names):
        total += 1
        obj = obj_map.get(name)
        if not obj:
            print(f"⚠️  WARNING: AddressObject '{name}' not found during tagging.")
            continue

        # obj.tag is a list of tag names attached to this Address Object in PAN-OS
        current_tags = list(obj.tag or [])
        if tag_name not in current_tags:
            current_tags.append(tag_name)
            obj.tag = current_tags
            obj.apply()  # push the modified object to candidate config
            updated += 1
        # If the tag is already present, we leave it untouched (idempotent).
    return updated, total


def find_static_group(fw: Firewall, name: str) -> Optional[AddressGroup]:
    """
    Find the Address Group object with the given name.

    Python side:
      - Reads all groups (already pulled in load_maps in many flows, but we keep
        this lookup separate for early validation and user-friendly errors).

    PAN-OS side:
      - AddressGroup.refreshall performs a read of configured groups (no changes).
    """
    groups = AddressGroup.refreshall(fw, add=False) or []
    for g in groups:
        if g.name == name:
            return g
    return None


# =========================
# Main execution
# =========================
def main():
    try:
        # Establish the session manager object. First read/write triggers auth handshake.
        fw = connect_firewall()
        print(f"✅ Connected to firewall {FIREWALL_IP}")

        # Validate that the target group exists and is STATIC (not dynamic).
        target = find_static_group(fw, TARGET_STATIC_GROUP)
        if target is None:
            sys.exit(f"❌ ERROR: Address Group '{TARGET_STATIC_GROUP}' not found on the firewall.")

        if target.static_value is None:
            # In PAN-OS, a Dynamic Address Group has a filter (dynamic_value) instead of static_value.
            sys.exit(f"❌ ERROR: Address Group '{TARGET_STATIC_GROUP}' is not STATIC (it may already be dynamic).")

        print(f"🔍 Found STATIC group '{TARGET_STATIC_GROUP}' with {len(target.static_value)} direct members.")

        # Build fast lookup maps for objects and groups (one-time read).
        obj_map, grp_map = load_maps(fw)

        # Recursively flatten nested groups → a unique set of Address Object names.
        resolved_object_names = collect_all_address_objects_from_group(target, obj_map, grp_map)

        if not resolved_object_names:
            # If we can't resolve any Address Objects, there's nothing to tag.
            sys.exit("❌ ERROR: No valid AddressObjects found in the group hierarchy.")

        print(f"📦 Resolved {len(resolved_object_names)} unique AddressObject(s) after recursive expansion.")

        # Make sure the desired tag exists as a PAN-OS Tag object (candidate config only).
        ensure_tag(fw, DYNAMIC_MATCH_TAG)
        print(f"🏷️  Tag '{DYNAMIC_MATCH_TAG}' ensured on the firewall (candidate config).")

        # Apply the tag to each Address Object, pushing updates into the candidate config.
        updated, total = tag_objects(obj_map, resolved_object_names, DYNAMIC_MATCH_TAG)
        print(f"✅ Tagged {updated}/{total} AddressObject(s) with '{DYNAMIC_MATCH_TAG}' (candidate config updated).")

        # Explicit note on commit behavior for change control clarity.
        print("\n⚠️  NOTE: All changes are currently in the CANDIDATE configuration.")
        print("📝  You must manually COMMIT on the firewall for these changes to take effect.\n")
        print("🎉 Done. (No Dynamic Address Group was created by this script.)")

    except PanDeviceError as e:
        # Common bucket for API errors (auth, permissions, malformed requests, etc.)
        sys.exit(f"❌ PAN-OS API error: {e}")
    except KeyboardInterrupt:
        sys.exit("🛑 Aborted by user.")
    except Exception as e:
        # Last-resort catch so the script exits cleanly with context.
        sys.exit(f"❌ Unexpected error: {e}")


if __name__ == "__main__":
    main()
