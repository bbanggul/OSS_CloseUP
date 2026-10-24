"""Range-confirmed fix versions. Mirrors frontend/src/display.js rangeFixFor and
frontend/src/packageGroups.js commonFixVersion so the report and the screen agree."""
import re

_SEMVER = re.compile(r'^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$')


def parse(value):
    m = _SEMVER.match(str(value if value is not None else '').strip())
    return ((int(m[1]), int(m[2]), int(m[3])), m[4]) if m else None


def compare(a, b):
    x, y = parse(a), parse(b)
    if not x or not y:
        return None
    if x[0] != y[0]:
        return -1 if x[0] < y[0] else 1
    if x[1] == y[1]:
        return 0
    if not x[1]:
        return 1
    if not y[1]:
        return -1
    return -1 if x[1] < y[1] else 1


def _at_or_after(version, start):
    # Same as JS `compareSemver(v, start) >= 0`, where an uncomparable value (null) also passes.
    if start == '0':
        return True
    c = compare(version, start)
    return c is None or c >= 0


def _ranges(candidates):
    for c in candidates or []:
        r = c.get('range') if isinstance(c, dict) else None
        if isinstance(r, dict) and isinstance(r.get('events'), list) and r.get('type', 'SEMVER') == 'SEMVER':
            yield r['events']


def range_fix(installed, candidates):
    """Highest fixed version whose range contains the installed version, else None."""
    if not parse(installed):
        return None
    matches = []
    for events in _ranges(candidates):
        introduced = None
        for e in events:
            if not isinstance(e, dict):
                continue
            if 'introduced' in e:
                introduced = str(e['introduced'])
            elif 'fixed' in e and introduced is not None:
                fixed = str(e['fixed'])
                after = _at_or_after(installed, introduced)
                if after and compare(installed, fixed) == -1 and parse(fixed):
                    matches.append(fixed)
                introduced = None
    if not matches:
        return None
    best = matches[0]
    for v in matches[1:]:
        if compare(v, best) == 1:
            best = v
    return best


def _affected(version, candidates):
    readable = False
    for events in _ranges(candidates):
        readable = True
        introduced = None
        for e in events:
            if not isinstance(e, dict):
                continue
            if 'introduced' in e:
                if introduced is not None:
                    return None
                introduced = str(e['introduced'])
            elif introduced is not None and ('fixed' in e or 'last_affected' in e):
                end = str(e.get('fixed', e.get('last_affected')))
                after = _at_or_after(version, introduced)
                cmp = compare(version, end)
                if cmp is None:
                    return None
                if after and (cmp == -1 if 'fixed' in e else cmp <= 0):
                    return True
                introduced = None
        if introduced is not None and _at_or_after(version, introduced):
            return True
    return False if readable else None


def _major_change(a, b):
    x, y = parse(a), parse(b)
    if not x or not y:
        return False
    return x[0][0] != y[0][0] or (x[0][0] == 0 and x[0][1] != y[0][1])


def common_fix(installed, candidate_lists):
    """candidate_lists: one candidate list per finding of the same installed package."""
    total = len(candidate_lists)
    targets = [t for t in (range_fix(installed, c) for c in candidate_lists) if t]
    if not targets:
        return {'status': 'none', 'total': total, 'covered': 0}
    version = targets[0]
    for t in targets[1:]:
        if compare(t, version) == 1:
            version = t
    checks = [_affected(version, c) for c in candidate_lists]
    base = {'version': version, 'total': total, 'major_change': _major_change(installed, version)}
    if any(range_fix(installed, c) and checks[i] is True for i, c in enumerate(candidate_lists)):
        return {**base, 'status': 'conflict', 'covered': 0}
    covered = sum(1 for x in checks if x is False)
    return {**base, 'status': 'all' if covered == total else 'partial', 'covered': covered}
