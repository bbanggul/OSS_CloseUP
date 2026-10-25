"""Trivy vulnerability DB refresh policy: download at most once per refresh period (default one day).

Within the period Trivy runs against the cached DB without contacting the DB source.
A marker file records when the last successful download-enabled run finished; the marker is
ignored when the cached DB file itself is missing, so a wiped cache is always re-downloaded.
"""
import os
import time
from pathlib import Path

REFRESH_SECONDS = int(os.getenv('VULN_DB_REFRESH_SECONDS', '86400'))
TRIVY_CACHE = Path(os.getenv('TRIVY_CACHE_DIR', '/cache/trivy'))


def _marker(cache_dir, name):
    return Path(cache_dir) / f'.{name}-downloaded-at'


def _db_present(cache_dir, name):
    return (Path(cache_dir) / 'db' / f'{name}.db').is_file()


def is_fresh(cache_dir, name, now=None):
    """True when the cached DB exists and was downloaded within the refresh period."""
    now = time.time() if now is None else now
    try:
        downloaded_at = float(_marker(cache_dir, name).read_text().strip())
    except (OSError, ValueError):
        return False
    return _db_present(cache_dir, name) and 0 <= now - downloaded_at < REFRESH_SECONDS


def mark_downloaded(cache_dir, name, now=None):
    """Record a successful download-enabled run. Failure to write only means the next run refreshes."""
    try:
        _marker(cache_dir, name).write_text(str(time.time() if now is None else now))
    except OSError:
        pass


def policy():
    """Whether Trivy may use its cached DB only, for this scan."""
    return {'trivy': is_fresh(TRIVY_CACHE, 'trivy')}
