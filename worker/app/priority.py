"""Pure priority-io-v2 calculator; no database, network, or LLM access.

The adapter owns scan membership, tool-result interpretation, and DB transactions.
Only the supplied security_status determines completeness (not scan_runs.status).
"""

from collections import defaultdict
from copy import deepcopy
from uuid import UUID


SCHEMA_VERSION = 'priority-io-v2'
RULE_VERSION = 'priority-v1'
SEVERITY_PRIORITY = {
    'CRITICAL': 'P0', 'HIGH': 'P1', 'MEDIUM': 'P2', 'LOW': 'P3',
    'UNKNOWN': None,
}
PRIORITY_ORDER = {'P0': 0, 'P1': 1, 'P2': 2, 'P3': 3, None: 4}


class PriorityInputError(ValueError):
    """Reject this priority batch; preserve scan results and error evidence.

    This exception must never roll back independently saved scanner artifacts or
    valid scanner results. Use priority_stage.run_priority_stage at the boundary.
    """

    def __init__(self, code, field_path, message):
        self.code = code
        self.field_path = field_path
        super().__init__(f'{code} at {field_path}: {message}')


def _error(code, path, message):
    raise PriorityInputError(code, path, message)


def _object(value, path):
    if not isinstance(value, dict):
        _error('INVALID_TYPE', path, 'Expected an object')
    return value


def _field(obj, key, path=''):
    field_path = f'{path}.{key}' if path else key
    if key not in obj:
        _error('MISSING_FIELD', field_path, 'Required field is missing')
    return obj[key]


def _array(value, path):
    if not isinstance(value, list):
        _error('INVALID_TYPE', path, 'Expected an array')
    return value


def _string(value, path):
    if not isinstance(value, str):
        _error('INVALID_TYPE', path, 'Expected a string')
    return value


def _enum(value, choices, path):
    _string(value, path)
    if value not in choices:
        _error('INVALID_VALUE', path, 'Unsupported value')
    return value


def _uuid(value, path):
    _string(value, path)
    try:
        # Compare UUID identities, even if a caller uses uppercase or compact text.
        return UUID(value)
    except ValueError:
        _error('INVALID_UUID', path, 'Expected a UUID string')


def _validate(payload, allow_test_data=False):
    _object(payload, '$')
    _enum(_field(payload, 'schema_version'), (SCHEMA_VERSION,), 'schema_version')
    if type(payload.get('test_only', False)) is not bool:
        _error('INVALID_TYPE', 'test_only', 'Expected a boolean')
    if payload.get('test_only') and not allow_test_data:
        _error('TEST_DATA_NOT_ALLOWED', 'test_only', 'Test data cannot be used in production')
    _uuid(_field(payload, 'scan_id'), 'scan_id')
    status = _enum(_field(payload, 'security_status'),
                   ('completed', 'partial', 'failed'), 'security_status')
    tools = _object(_field(payload, 'tool_status'), 'tool_status')
    for tool in ('trivy', 'osv'):
        path = f'tool_status.{tool}'
        row = _object(_field(tools, tool, 'tool_status'), path)
        value = _string(_field(row, 'status', path), f'{path}.status')
        if not value:
            _error('INVALID_VALUE', f'{path}.status', 'Status must not be empty')
    # Tool-specific status vocabulary is adapter-owned. A normalization failure
    # may invalidate outputs even when the scanner process itself completed.
    package_rows = _array(_field(payload, 'packages'), 'packages')
    finding_rows = _array(_field(payload, 'findings'), 'findings')
    link_rows = _array(_field(payload, 'finding_packages'), 'finding_packages')
    packages, findings, links = {}, {}, []
    for index, row in enumerate(package_rows):
        path = f'packages[{index}]'
        _object(row, path)
        identity = _uuid(_field(row, 'package_id', path), f'{path}.package_id')
        if identity in packages:
            _error('DUPLICATE_PACKAGE_ID', f'{path}.package_id', 'Duplicate package ID')
        _string(_field(row, 'name', path), f'{path}.name')
        version = _field(row, 'installed_version', path)
        if version is not None:
            _string(version, f'{path}.installed_version')
        _enum(_field(row, 'relationship', path),
              ('direct', 'indirect', 'unknown'), f'{path}.relationship')
        packages[identity] = row
    for index, row in enumerate(finding_rows):
        path = f'findings[{index}]'
        _object(row, path)
        identity = _uuid(_field(row, 'finding_id', path), f'{path}.finding_id')
        if identity in findings:
            _error('DUPLICATE_FINDING_ID', f'{path}.finding_id', 'Duplicate Finding ID')
        _enum(_field(row, 'severity', path), SEVERITY_PRIORITY, f'{path}.severity')
        if row.get('priority_input_eligible', True) is not True:
            _error('SEVERITY_REVIEW_REQUIRED', path, 'Unsupported source severity requires review')
        for observation in _array(row.get('severity_observations', []), f'{path}.severity_observations'):
            _object(observation, f'{path}.severity_observations')
            raw = observation.get('raw')
            if (raw is not None and raw != '' and
                    (not isinstance(raw, str) or raw.upper() not in (*SEVERITY_PRIORITY, 'MODERATE'))):
                _error('SEVERITY_REVIEW_REQUIRED', path, 'Unsupported source severity requires review')
        findings[identity] = row
    seen = set()
    for index, row in enumerate(link_rows):
        path = f'finding_packages[{index}]'
        _object(row, path)
        fid = _uuid(_field(row, 'finding_id', path), f'{path}.finding_id')
        pid = _uuid(_field(row, 'package_id', path), f'{path}.package_id')
        if fid not in findings:
            _error('UNKNOWN_FINDING_ID', f'{path}.finding_id', 'Finding is not in this payload')
        if pid not in packages:
            _error('UNKNOWN_PACKAGE_ID', f'{path}.package_id', 'Package is not in this payload')
        if (fid, pid) in seen:
            _error('DUPLICATE_LINK', path, 'Duplicate Finding-package connection')
        seen.add((fid, pid))
        fix = _enum(_field(row, 'fix_information', path),
                    ('candidates_available', 'not_reported', 'unknown', 'failed'),
                    f'{path}.fix_information')
        candidates = _array(_field(row, 'fixed_version_candidates', path),
                            f'{path}.fixed_version_candidates')
        for candidate_index, candidate in enumerate(candidates):
            cpath = f'{path}.fixed_version_candidates[{candidate_index}]'
            _object(candidate, cpath)
            if not any(isinstance(candidate.get(k), str) and candidate[k].strip() for k in ('value', 'raw')):
                _error('EMPTY_FIX_CANDIDATE', cpath, 'A reported candidate needs its original value')
            source = _string(_field(candidate, 'source_tool', cpath), f'{cpath}.source_tool')
            if not source.strip():
                _error('INVALID_VALUE', f'{cpath}.source_tool', 'Candidate source must not be empty')
            if type(candidate.get('test_only', False)) is not bool:
                _error('INVALID_TYPE', f'{cpath}.test_only', 'Expected a boolean')
            if candidate.get('test_only') and not (allow_test_data and payload.get('test_only')):
                _error('TEST_DATA_NOT_ALLOWED', cpath, 'Test candidates require an explicit test payload')
        if (fix == 'candidates_available') != bool(candidates):
            _error('FIX_INFORMATION_MISMATCH', f'{path}.fix_information',
                   'Candidate presence contradicts fix_information')
        links.append((fid, pid, fix == 'candidates_available'))
    if status == 'failed' and (finding_rows or link_rows):
        _error('FAILED_WITH_FINDINGS', 'findings',
               'Failed security results must not contain Findings or links')
    return packages, findings, links


def calculate_priorities(payload, *, allow_test_data=False):
    """Validate the entire input and return sorted, newly allocated results.

    Raises PriorityInputError(code, field_path, message); never returns partial
    results. Unknown extra fields are ignored, not edited. No source evidence,
    candidate versions, severity, or review flags are modified.
    """
    packages, findings, links = _validate(payload, allow_test_data)
    source_links = {(UUID(row['finding_id']), UUID(row['package_id'])): row
                    for row in payload['finding_packages']}
    security_status = payload['security_status']
    links_by_package = defaultdict(list)
    mapped = set()
    link_results = []
    for fid, pid, has_candidate in links:
        finding = findings[fid]
        priority = SEVERITY_PRIORITY[finding['severity']]
        row = {
            'finding_id': finding['finding_id'],
            'package_id': packages[pid]['package_id'],
            'priority': priority,
            'priority_status': 'severity_unknown' if priority is None else 'calculated',
            'has_fix_candidate': has_candidate,
            'priority_rule_version': RULE_VERSION,
            'package_name': packages[pid]['name'],
            'installed_version': packages[pid]['installed_version'],
            'fix_information': source_links[fid, pid]['fix_information'],
            'fixed_version_candidates': deepcopy(source_links[fid, pid]['fixed_version_candidates']),
            'finding_context': deepcopy({key: finding[key] for key in (
                'severity', 'severity_observations', 'severity_conflict', 'evidence',
                'review_status', 'review_reasons', 'manual_review_required') if key in finding}),
            'link_evidence': deepcopy(source_links[fid, pid].get('evidence', {})),
        }
        link_results.append(row)
        links_by_package[pid].append(row)
        mapped.add(fid)

    package_results = []
    for pid, package in packages.items():
        rows = links_by_package[pid]
        known = [row for row in rows if row['priority'] is not None]
        priority = min((row['priority'] for row in known),
                       key=PRIORITY_ORDER.__getitem__, default=None)
        representatives = [row for row in known if row['priority'] == priority]
        if known:
            status = 'calculated'
        elif rows:
            status = 'severity_unknown'
        else:
            status = 'no_findings' if security_status == 'completed' else 'unavailable'
        package_results.append({
            'package_id': package['package_id'],
            'package_name': package['name'],
            'installed_version': package['installed_version'],
            'priority': priority,
            'priority_status': status,
            'representative_finding_ids': sorted(row['finding_id'] for row in representatives),
            'has_fix_candidate_at_priority': any(row['has_fix_candidate'] for row in representatives),
            'unknown_finding_count': sum(row['priority'] is None for row in rows),
            'incomplete': security_status != 'completed',
            'representative_links': sorted(deepcopy(representatives), key=lambda row: row['finding_id']),
        })

    def package_name_version(package_id):
        package = packages[UUID(package_id)]
        return package['name'], package['installed_version'] or ''

    def link_key(row):
        # UNKNOWN has no candidate-based ranking, even if a candidate exists.
        candidate_rank = int(not row['has_fix_candidate']) if row['priority'] else 0
        return (PRIORITY_ORDER[row['priority']], candidate_rank,
                *package_name_version(row['package_id']), row['finding_id'], row['package_id'])

    def package_key(row):
        if row['priority'] is not None:
            rank = PRIORITY_ORDER[row['priority']]
            candidate_rank = int(not row['has_fix_candidate_at_priority'])
        else:
            rank = {'severity_unknown': 4, 'no_findings': 5, 'unavailable': 6}[row['priority_status']]
            candidate_rank = 0
        return (rank, candidate_rank, *package_name_version(row['package_id']), row['package_id'])

    return {
        'schema_version': SCHEMA_VERSION,
        'scan_id': payload['scan_id'],
        'priority_rule_version': RULE_VERSION,
        'security_status': security_status,
        'test_only': payload.get('test_only', False),
        'link_results': sorted(link_results, key=link_key),
        'package_results': sorted(package_results, key=package_key),
        'unmapped_finding_ids': sorted(findings[fid]['finding_id'] for fid in findings if fid not in mapped),
        'summary': {
            'finding_count': len(findings),
            'unknown_finding_count': sum(f['severity'] == 'UNKNOWN' for f in findings.values()),
            'package_count': len(packages),
            'affected_package_count': len({pid for _, pid, _ in links}),
            'unknown_package_count': sum(r['unknown_finding_count'] > 0 for r in package_results),
            'link_count': len(links),
        },
    }
