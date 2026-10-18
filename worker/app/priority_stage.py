"""D07 persistence boundary, independent of the application's DB driver.

The supplied store must commit each method independently: evidence first,
atomic priority publication second, or an error record in a separate transaction.
Do not put this call inside an outer transaction that rolls back scan evidence.
"""

from copy import deepcopy
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID, uuid4

from .priority import PriorityInputError, RULE_VERSION, SCHEMA_VERSION, calculate_priorities


STAGE_VERSION = 'priority-stage-v1'


class PriorityStageStore(Protocol):
    """Persistence adapter contract; this protocol is not a production DB adapter.

    save_scan_evidence: durably preserve raw results, independently validated scan
    results, and tool/error evidence. Return only after commit. Never derive these
    records from the potentially invalid priority payload.

    save_priority_result: atomically publish ALL link/package results and the
    success record. On exception roll back ONLY that priority transaction.
    Enforce scan/attempt membership, source revision and worker fencing here.

    save_priority_error: commit an append-only error record after any priority
    rollback. Preserve previous valid priorities as history, but mark this new
    evaluation unavailable so old values are not displayed as its current result.

    None of these methods may delete/replace scanner evidence to handle a priority
    error. A concrete adapter must merge metadata without replacing other stages.
    """

    def save_scan_evidence(self, record: dict) -> None: ...

    def save_priority_result(self, record: dict) -> None: ...

    def save_priority_error(self, record: dict) -> None: ...


class PriorityStagePersistenceError(RuntimeError):
    """Evidence/error persistence was not confirmed; never report normal success.

    record is retained for explicit retry/logging by the caller. A storage outage
    cannot promise durability; the caller must retain existing raw artifact files.
    """

    def __init__(self, stage, record, *, scan_evidence_saved):
        self.stage = stage
        self.record = deepcopy(record)
        self.scan_evidence_saved = scan_evidence_saved
        super().__init__(f'Priority stage persistence failed: {stage}')


def run_priority_stage(*, scan_id, attempt_id, raw_results, valid_results,
                       tool_status, build_payload, store: PriorityStageStore):
    """Persist scan evidence, then build/validate/publish the priority batch.

    scan_id/attempt_id must come from the worker, not from untrusted payload IDs.
    valid_results must have passed the scanner/normalizer's own validation. They
    are scan results, not partially accepted priority calculations.
    build_payload receives a private copy of the committed evidence record.
    Known adapter input failures should raise PriorityInputError(code,path,msg).
    No test-data override is exposed through this production boundary.
    """
    # Without trusted scope there is nowhere safe to associate new evidence.
    scan_id, attempt_id = str(UUID(str(scan_id))), str(UUID(str(attempt_id)))
    base = {
        'stage_version': STAGE_VERSION, 'evaluation_id': str(uuid4()),
        'scan_id': scan_id, 'attempt_id': attempt_id,
        'started_at': datetime.now(timezone.utc).isoformat(),
        'schema_version': SCHEMA_VERSION, 'priority_rule_version': RULE_VERSION,
    }
    evidence = {**base, 'raw_results': deepcopy(raw_results),
                'valid_results': deepcopy(valid_results), 'tool_status': deepcopy(tool_status)}
    try:
        store.save_scan_evidence(deepcopy(evidence))
    except Exception as exc:
        raise PriorityStagePersistenceError('scan_evidence', evidence, scan_evidence_saved=False) from exc

    stage, payload, snapshot = 'input_build', None, None
    try:
        payload = build_payload(deepcopy(evidence))
        snapshot = deepcopy(payload)
        stage = 'calculation'
        result = calculate_priorities(payload)
        if UUID(result['scan_id']) != UUID(scan_id):
            raise PriorityInputError('SCAN_SCOPE_MISMATCH', 'scan_id',
                                     'Priority payload belongs to another scan')
        record = {**base, 'status': 'completed', 'current_result_available': True,
                  'result': result, 'error': None}
        stage = 'priority_storage'
        store.save_priority_result(deepcopy(record))
    except Exception as exc:
        # Input errors invalidate the entire priority batch, never the independent
        # scanner evidence. Storage exceptions are not input-validation failures.
        invalid = isinstance(exc, PriorityInputError) and stage != 'priority_storage'
        code = exc.code if invalid else {
            'input_build': 'PRIORITY_INPUT_BUILD_FAILED',
            'calculation': 'PRIORITY_CALCULATION_FAILED',
            'priority_storage': 'PRIORITY_WRITE_FAILED',
        }[stage]
        record = {
            **base, 'status': 'invalid_input' if invalid else 'failed',
            'current_result_available': False, 'result': None,
            'error': {'stage': stage, 'code': code,
                      'field_path': exc.field_path if invalid else None,
                      'message': str(exc), 'exception_type': type(exc).__name__},
            'attempted_payload': snapshot,
        }
        try:
            store.save_priority_error(deepcopy(record))
        except Exception as storage_exc:
            raise PriorityStagePersistenceError('priority_error', record, scan_evidence_saved=True) from storage_exc
    return {**record, 'scan_evidence_saved': True,
            'priority_saved': record['status'] == 'completed',
            'error_saved': record['status'] != 'completed'}
