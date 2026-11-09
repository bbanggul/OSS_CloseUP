"""Read the authoritative package view using the caller's transaction."""
from .priority_view import load_priority
from .package_view import build_view
from .scan_material import load_scan_material


def load_package_view(conn, scan_id):
    material = load_scan_material(conn, scan_id)
    scan = material['scan']
    state, result = load_priority(conn, scan_id, scan['tool_status'])
    return build_view(scan, material['packages'], material['findings'], material['links'], state, result)
