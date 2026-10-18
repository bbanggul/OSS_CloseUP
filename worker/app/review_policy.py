"""D03/D05 internal display policies, independent of security priority.

These functions do not fetch repository data, decide legal compliance, choose a
license alternative, or infer maintenance risk from dates.
"""

from copy import deepcopy
from datetime import datetime, timezone
import re


ACTIVITY_RULE_VERSION = 'activity-facts-v1'
LICENSE_RULE_VERSION = 'license-review-v1'
GENERAL_LICENSES = frozenset(('MIT', 'Apache-2.0', 'BSD-3-Clause', 'ISC'))
IDENTIFIER = r'[A-Za-z0-9][A-Za-z0-9.+-]*'


def evaluate_license(raw_license, *, project_license=None):
    """Preserve raw input; only recognize a single ID or simple binary OR/AND.

    Complex or malformed expressions remain unparsed and require manual review.
    '일반' is an internal label and never means absence of license obligations.
    """
    expression = None
    status = '확인 필요'
    if raw_license is None or (isinstance(raw_license, str) and not raw_license.strip()):
        reason = 'license_missing'
    elif not isinstance(raw_license, str):
        reason = 'expression_unparsed'
    else:
        text = raw_license.strip()
        match = re.fullmatch(rf'({IDENTIFIER})\s+(OR|AND)\s+({IDENTIFIER})', text)
        if match and match[1] not in ('OR', 'AND', 'WITH') and match[3] not in ('OR', 'AND', 'WITH'):
            expression = {'operator': match[2], 'operands': [match[1], match[3]]}
            reason = 'alternative_selection_review' if match[2] == 'OR' else 'combined_terms_review'
        elif re.fullmatch(IDENTIFIER, text) and text not in ('OR', 'AND', 'WITH'):
            if text in GENERAL_LICENSES:
                status, reason = '일반', 'listed_general_license'
            elif re.fullmatch(r'(?:A|L)?GPL-\d[^\s]*', text):
                reason = 'copyleft_review'
            else:
                reason = 'license_not_in_policy'
        else:
            reason = 'expression_unparsed'
    messages = {
        'license_missing': '라이선스 정보 확인 필요',
        'listed_general_license': '내부 일반 표시 대상이며 고지 등 적용 조건 확인은 필요합니다.',
        'copyleft_review': '사용·배포 방식에 따른 적용 조건 확인 필요',
        'license_not_in_policy': '내부 정책표 밖의 라이선스 확인 필요',
        'alternative_selection_review': '대안 중 실제 적용 조건 선택 확인',
        'combined_terms_review': '각 조건의 함께 적용 여부 확인',
        'expression_unparsed': '표현식 해석 불가: 원문 확인 필요',
    }
    return {
        'license_rule_version': LICENSE_RULE_VERSION,
        'license_status': status, 'reason_code': reason, 'reason': messages[reason],
        'raw_license': deepcopy(raw_license), 'project_license': deepcopy(project_license),
        'expression': expression, 'automatic_selection': None,
        'legal_compliance_guarantee': False, 'legal_violation_assertion': False,
        'security_priority_effect': 'none',
    }


def _timestamp(value):
    if not isinstance(value, str):
        raise ValueError('Expected a timezone-aware timestamp')
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('Expected a timezone-aware timestamp')
    return stamp.astimezone(timezone.utc)


def evaluate_activity(facts, *, as_of):
    """Display facts with independent field availability and fixed UTC ages.

    facts: github_status=ok/unavailable/failed, archived=bool/null,
    last_commit_at/last_release_at=ISO timestamp/null, optional field_status and
    field_errors keyed by those three field names. Explicit per-field status
    overrides overall fetch status, retaining successful partial observations.
    """
    if not isinstance(facts, dict):
        raise ValueError('Activity facts must be an object')
    now = _timestamp(as_of)
    statuses = facts.get('field_status', {})
    errors = facts.get('field_errors', {})
    if not isinstance(statuses, dict) or not isinstance(errors, dict):
        raise ValueError('field_status and field_errors must be objects')

    def availability(key):
        status = statuses.get(key, 'ok' if facts.get('github_status') == 'ok' else 'unknown')
        if status not in ('ok', 'failed', 'unknown'):
            raise ValueError(f'Unsupported activity field status: {key}')
        return status

    archived = facts.get('archived')
    archive_status = availability('archived')
    confirmed = archive_status == 'ok' and type(archived) is bool
    state = ('Archived' if archived else 'Facts only') if confirmed else 'Unknown'
    result = {
        'activity_rule_version': ACTIVITY_RULE_VERSION,
        'maintenance_status': state,
        'display_label': {'Archived': 'Archived', 'Facts only': '활동 정보', 'Unknown': '확인 불가'}[state],
        'archived': archived if confirmed else None,
        'archived_status': 'available' if confirmed else 'unavailable',
        'archived_error': deepcopy(errors.get('archived')),
        'github_status': facts.get('github_status'), 'as_of': as_of,
        'automatic_risk_classification': False, 'threshold_enabled': False,
        'security_priority_effect': 'none', 'deprecated': deepcopy(facts.get('deprecated')),
        'evidence': deepcopy(facts),
    }
    for short, key in (('commit', 'last_commit_at'), ('release', 'last_release_at')):
        raw = facts.get(key)
        elapsed = None
        field_status = availability(key)
        if field_status != 'ok':
            state, label = 'unavailable', '확인 불가'
        elif raw is None:
            state, label = 'missing', '정보 없음'
        else:
            try:
                seconds = (now - _timestamp(raw)).total_seconds()
            except (ValueError, TypeError, OverflowError):
                state, label = 'invalid', '입력 이상'
            else:
                if seconds < 0:
                    state, label = 'future', '입력 이상'
                else:
                    elapsed = int(seconds // 86400)
                    state, label = 'available', raw
        result.update({key: deepcopy(raw), f'{short}_status': state,
                       f'{short}_display': label, f'{short}_elapsed_days': elapsed,
                       f'{short}_error': deepcopy(errors.get(key))})
    return result
