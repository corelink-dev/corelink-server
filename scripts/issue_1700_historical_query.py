#!/usr/bin/env python3
"""One bounded, dry Workers Telemetry query for the exact failed v8 runtime run."""
import hashlib
import json
import os
from pathlib import Path
import urllib.error
import urllib.request

ACCOUNT = '6a1fc1c626fc2628823e60b9db01f5cd'
BASE = 'https://api.cloudflare.com/client/v4'
QUERY_PATH = f'/accounts/{ACCOUNT}/workers/observability/telemetry/query'
SOURCE_SHA = '14792a9eb416a3b9426f569d7d1f77079805c13f'
VERSION = '725b8a68-523e-42fb-a8b9-b7e1a720fdd0'
RELEASE = SOURCE_SHA
START = 1790827810000  # 2026-10-01T04:10:10Z, exact hosted probe start
END = 1790829312000    # 2026-10-01T04:35:12Z, exact receipt timeout
NONCE = 'issue-1700-recovery-20261001-v8'
OLD_RELEASE = '0f785fb9b096afe01247f1057d46377b9f604f13'
V5_RELEASE = 'cc32b3d819181bf9175e795868f66212aa5456c1'
PREFIX = '[staging_d1_runtime_probe]'
RECEIPT_PREFIX = PREFIX + ' receipt='
LIMIT = 100
NATIVE_KEYS = (
    'parameterized_select', 'failed_batch_observed', 'rollback_absence_verified',
    'probe_table_dropped', 'd1_binding_intercepted', 'authorization_absent',
    'cf_api_token_absent',
)
RETIREMENT_KEYS = (
    'old_probe_retired', 'old_probe_tables_absent', 'v5_probe_retired',
    'v5_probe_tables_absent', 'v4_probe_catalog_absent',
)
RECEIPT_KEYS = frozenset((
    'contract', 'probe_nonce', 'outcome', 'worker_release', 'scheduled_time_ms',
    *NATIVE_KEYS, 'old_probe_release', 'old_probe_retired', 'old_probe_tables_absent',
    'v5_probe_release', 'v5_probe_retired', 'v5_probe_tables_absent',
    'v5_prior_execution', 'v4_probe_catalog_absent',
))
QUERY = {
    'queryId': 'issue1700-run36812790564-v8-readonly',
    'dry': True,
    'view': 'events',
    'limit': LIMIT,
    'timeframe': {'from': START, 'to': END},
    'parameters': {'filterCombination': 'and', 'filters': [
        {'key': '$metadata.service', 'operation': 'eq', 'type': 'string', 'value': 'corelink-staging'},
        {'key': '$metadata.message', 'operation': 'includes', 'type': 'string', 'value': PREFIX},
    ]},
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def request(path, body):
    if path != QUERY_PATH or body != QUERY:
        raise ValueError('request_not_allowlisted')
    token = os.environ.get('CLOUDFLARE_API_TOKEN', '')
    if not token:
        raise ValueError('token_unavailable')

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body, separators=(',', ':')).encode(),
        headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        response = urllib.request.build_opener(NoRedirect).open(req, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError('response_bound')
        return response.status, json.loads(raw)


def _is_exact_receipt(receipt):
    return (
        isinstance(receipt, dict) and set(receipt) == RECEIPT_KEYS and
        receipt.get('contract') == 'corelink-staging-d1-binding-runtime-v1' and
        receipt.get('probe_nonce') == NONCE and receipt.get('outcome') == 'pass' and
        receipt.get('worker_release') == RELEASE and
        type(receipt.get('scheduled_time_ms')) is int and START <= receipt['scheduled_time_ms'] <= END and
        receipt.get('old_probe_release') == OLD_RELEASE and
        receipt.get('v5_probe_release') == V5_RELEASE and
        receipt.get('v5_prior_execution') == 'unknown' and
        all(receipt.get(key) is True for key in (*NATIVE_KEYS, *RETIREMENT_KEYS))
    )


def classify(body):
    result = body.get('result') if isinstance(body, dict) else None
    run = result.get('run') if isinstance(result, dict) else None
    events_envelope = result.get('events') if isinstance(result, dict) else None
    events = events_envelope.get('events') if isinstance(events_envelope, dict) else None
    if not isinstance(events, list) or len(events) > LIMIT:
        raise ValueError('event_envelope')
    total = events_envelope.get('count')
    if type(total) is not int or total < len(events):
        raise ValueError('event_count')
    counts = {
        'events_returned': len(events), 'events_matching_query': total,
        'service_match': 0, 'version_match': 0, 'scheduled_event': 0,
        'timestamp_in_window': 0, 'probe_prefix': 0, 'eligible_candidate_event': 0,
        'receipt_prefix': 0, 'valid_20_key_receipt': 0, 'malformed_receipt': 0,
        'rejected_receipt': 0, 'failure_probe_failed': 0,
        'rejected_staging_guard': 0,
    }
    receipt_predicates = dict.fromkeys((
        'exact_20_keys', 'contract', 'nonce', 'outcome', 'worker_release',
        'scheduled_time_in_window', 'old_probe_release', 'old_probe_retired',
        'old_probe_tables_absent', 'v5_probe_release', 'v5_probe_retired',
        'v5_probe_tables_absent', 'v5_prior_execution_unknown', 'v4_probe_catalog_absent',
        *NATIVE_KEYS,
    ), 0)
    for event in events:
        if not isinstance(event, dict):
            continue
        metadata = event.get('$metadata')
        workers = event.get('$workers')
        metadata = metadata if isinstance(metadata, dict) else {}
        workers = workers if isinstance(workers, dict) else {}
        service_match = (workers.get('scriptName') == 'corelink-staging' or
                         metadata.get('service') == 'corelink-staging')
        script_version = workers.get('scriptVersion')
        version_match = isinstance(script_version, dict) and script_version.get('id') == VERSION
        event_type = workers.get('eventType')
        scheduled_event = event_type in ('scheduled', 'cron')
        timestamp = event.get('timestamp')
        timestamp_in_window = type(timestamp) is int and START <= timestamp <= END
        message = metadata.get('message')
        probe_prefix = isinstance(message, str) and message.startswith(PREFIX)
        for key, matched in (
            ('service_match', service_match), ('version_match', version_match),
            ('scheduled_event', scheduled_event), ('timestamp_in_window', timestamp_in_window),
            ('probe_prefix', probe_prefix),
        ):
            counts[key] += int(matched)
        eligible = all((service_match, version_match, scheduled_event, timestamp_in_window, probe_prefix))
        if not eligible:
            continue
        counts['eligible_candidate_event'] += 1
        if message == PREFIX + ' failed reason=probe_failed':
            counts['failure_probe_failed'] += 1
            continue
        if message == PREFIX + ' rejected reason=staging_guard':
            counts['rejected_staging_guard'] += 1
            continue
        if not message.startswith(RECEIPT_PREFIX):
            continue
        counts['receipt_prefix'] += 1
        try:
            receipt = json.loads(message[len(RECEIPT_PREFIX):])
        except (TypeError, ValueError):
            counts['malformed_receipt'] += 1
            continue
        if not isinstance(receipt, dict):
            counts['malformed_receipt'] += 1
            continue
        checks = {
            'exact_20_keys': set(receipt) == RECEIPT_KEYS,
            'contract': receipt.get('contract') == 'corelink-staging-d1-binding-runtime-v1',
            'nonce': receipt.get('probe_nonce') == NONCE,
            'outcome': receipt.get('outcome') == 'pass',
            'worker_release': receipt.get('worker_release') == RELEASE,
            'scheduled_time_in_window': type(receipt.get('scheduled_time_ms')) is int and START <= receipt['scheduled_time_ms'] <= END,
            'old_probe_release': receipt.get('old_probe_release') == OLD_RELEASE,
            'old_probe_retired': receipt.get('old_probe_retired') is True,
            'old_probe_tables_absent': receipt.get('old_probe_tables_absent') is True,
            'v5_probe_release': receipt.get('v5_probe_release') == V5_RELEASE,
            'v5_probe_retired': receipt.get('v5_probe_retired') is True,
            'v5_probe_tables_absent': receipt.get('v5_probe_tables_absent') is True,
            'v5_prior_execution_unknown': receipt.get('v5_prior_execution') == 'unknown',
            'v4_probe_catalog_absent': receipt.get('v4_probe_catalog_absent') is True,
            **{key: receipt.get(key) is True for key in NATIVE_KEYS},
        }
        for key, matched in checks.items():
            receipt_predicates[key] += int(matched)
        if _is_exact_receipt(receipt):
            counts['valid_20_key_receipt'] += 1
        else:
            counts['rejected_receipt'] += 1

    saturated = len(events) == LIMIT
    truncated = total > len(events)
    dry_confirmed = isinstance(run, dict) and run.get('dry') is True
    account_confirmed = isinstance(run, dict) and run.get('accountId') == ACCOUNT
    if truncated:
        classification = 'incomplete_limit_reached'
    elif not account_confirmed:
        classification = 'incomplete_account_not_confirmed'
    elif not dry_confirmed:
        classification = 'incomplete_dry_not_confirmed'
    elif counts['valid_20_key_receipt']:
        classification = 'candidate_receipt_observed'
    elif counts['failure_probe_failed']:
        classification = 'candidate_probe_failed_marker_observed'
    elif counts['rejected_staging_guard']:
        classification = 'candidate_staging_guard_marker_observed'
    elif counts['eligible_candidate_event']:
        classification = 'candidate_probe_marker_without_valid_receipt'
    elif counts['version_match']:
        classification = 'candidate_version_events_without_probe_marker'
    elif counts['events_returned']:
        classification = 'events_observed_no_candidate_receipt'
    else:
        classification = 'no_matching_events'
    return {
        'classification': classification,
        'candidate_receipt_observed': counts['valid_20_key_receipt'] > 0,
        'new_runtime_proof': False,
        'account_confirmed': account_confirmed,
        'dry_confirmed': dry_confirmed,
        'limit': LIMIT,
        'limit_saturated': saturated,
        'limit_truncated': truncated,
        'counts': counts,
        'receipt_predicate_true_counts': receipt_predicates,
    }


def collect(call=request):
    receipt = {
        'contract': 'issue1700-v8-runtime-diagnostic-v1', 'run_id': '36812790564',
        'candidate_source_sha': SOURCE_SHA, 'candidate_version_id': VERSION,
        'timeframe': QUERY['timeframe'], 'query_sha256': digest(QUERY),
        'classification': 'unknown', 'new_runtime_proof': False,
    }
    try:
        status, body = call(QUERY_PATH, QUERY)
        if status in (401, 403):
            receipt.update(classification='query_unauthorized' if status == 401 else 'query_forbidden',
                           query_http=status)
        elif status != 200 or not isinstance(body, dict) or body.get('success') is not True:
            receipt.update(classification='query_rejected', query_http=status)
        else:
            receipt.update(query_http=status, **classify(body))
    except Exception as error:
        # Never expose response text, provider details, or exception content.
        code = str(error) if str(error) in {
            'request_not_allowlisted', 'token_unavailable', 'response_bound',
            'event_envelope', 'event_count',
        } else 'bounded_query_error'
        receipt['classification'] = code
    return receipt


def main():
    if os.environ.get('EXPECTED_SHA') != os.environ.get('GITHUB_SHA') or not os.environ.get('EXPECTED_SHA'):
        raise SystemExit('exact workflow SHA required')
    if os.environ.get('GITHUB_RUN_ATTEMPT') != '1':
        raise SystemExit('workflow reruns are not permitted')
    output = Path(os.environ['RUNNER_TEMP']) / 'issue-1700-historical-classification.json'
    receipt = collect()
    output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    output.chmod(0o600)
    print(json.dumps({key: receipt[key] for key in (
        'classification', 'new_runtime_proof', 'candidate_receipt_observed',
        'limit_saturated', 'limit_truncated', 'counts', 'receipt_predicate_true_counts',
    ) if key in receipt}, sort_keys=True))
    return 0 if (receipt.get('query_http') == 200 and receipt.get('dry_confirmed') and
                 receipt.get('account_confirmed')) else 1


if __name__ == '__main__':
    raise SystemExit(main())
