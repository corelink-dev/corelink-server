#!/usr/bin/env python3
"""One fixed, non-persisting historical query; never executes the runtime probe."""
import hashlib
import json
import os
from pathlib import Path
import urllib.error
import urllib.request

ACCOUNT = '6a1fc1c626fc2628823e60b9db01f5cd'
BASE = 'https://api.cloudflare.com/client/v4'
QUERY_PATH = f'/accounts/{ACCOUNT}/workers/observability/telemetry/query'
START, END = 1790801501000, 1790801765000  # 2026-09-30 20:51:41..20:56:05 UTC
VERSION = '6fe4c25f-2767-4382-bb0e-6f03e6a1c992'
RELEASE = 'cc32b3d819181bf9175e795868f66212aa5456c1'
OLD_RELEASE = '0f785fb9b096afe01247f1057d46377b9f604f13'
NONCE = 'issue-1700-recovery-20260930-v5'
NATIVE_CHECKS = ('parameterized_select', 'failed_batch_observed', 'rollback_absence_verified',
                 'probe_table_dropped', 'd1_binding_intercepted', 'authorization_absent', 'cf_api_token_absent',
                 'old_probe_retired', 'old_probe_tables_absent', 'v4_probe_catalog_absent')
QUERY = {
    'queryId': 'issue1700-run36775268954-readonly', 'dry': True, 'view': 'events', 'limit': 100,
    'timeframe': {'from': START, 'to': END},
    'parameters': {'filterCombination': 'and', 'filters': [
        {'key': '$metadata.service', 'operation': 'eq', 'type': 'string', 'value': 'corelink-staging'},
        {'key': '$metadata.message', 'operation': 'includes', 'type': 'string',
         'value': '[staging_d1_runtime_probe]'},
    ]},
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def request(path, body=None):
    # No arbitrary URL, verb, pagination, retry, or redirected credential forwarding.
    if not ((path == f'/accounts/{ACCOUNT}' and body is None) or
            (path == QUERY_PATH and body == QUERY)):
        raise ValueError('request_not_allowlisted')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    req = urllib.request.Request(BASE + path, data=None if body is None else json.dumps(body).encode(),
        headers={'Authorization': 'Bearer ' + os.environ['CLOUDFLARE_API_TOKEN'],
                 'Content-Type': 'application/json'})
    try:
        response = urllib.request.build_opener(NoRedirect).open(req, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError('response_bound')
        return response.status, json.loads(raw), hashlib.sha256(raw).hexdigest()


def classify(body):
    # Shape follows cloudflare-python TelemetryQueryResponse.Events.EventsEvent.
    events = body.get('result', {}).get('events', {}).get('events')
    if not isinstance(events, list) or len(events) > 100:
        raise ValueError('event_envelope')
    receipts, failed = [], 0
    counts = dict.fromkeys(('object_event', 'worker_metadata', 'message_metadata',
        'exact_service', 'exact_version', 'scheduled_event', 'timestamp_in_window',
        'probe_prefix', 'receipt_prefix', 'eligible_event', 'malformed_receipt',
        'rejected_receipt'), 0)
    for event in events:
        if not isinstance(event, dict):
            continue
        counts['object_event'] += 1
        workers, metadata = event.get('$workers'), event.get('$metadata')
        counts['worker_metadata'] += isinstance(workers, dict)
        counts['message_metadata'] += isinstance(metadata, dict)
        workers = workers if isinstance(workers, dict) else {}
        metadata = metadata if isinstance(metadata, dict) else {}
        version = workers.get('scriptVersion')
        message = metadata.get('message')
        predicates = {
            'exact_service': workers.get('scriptName') == 'corelink-staging',
            'exact_version': isinstance(version, dict) and version.get('id') == VERSION,
            'scheduled_event': workers.get('eventType') in ('scheduled', 'cron'),
            'timestamp_in_window': type(event.get('timestamp')) is int and START <= event['timestamp'] <= END,
            'probe_prefix': isinstance(message, str) and message.startswith('[staging_d1_runtime_probe]'),
            'receipt_prefix': isinstance(message, str) and message.startswith('[staging_d1_runtime_probe] receipt='),
        }
        for key, matched in predicates.items():
            counts[key] += matched
        if not all(predicates[k] for k in ('exact_service', 'exact_version', 'scheduled_event', 'timestamp_in_window', 'probe_prefix')):
            continue
        counts['eligible_event'] += 1
        if message == '[staging_d1_runtime_probe] failed reason=probe_failed':
            failed += 1
        prefix = '[staging_d1_runtime_probe] receipt='
        if not isinstance(message, str) or not message.startswith(prefix):
            continue
        try:
            native = json.loads(message[len(prefix):])
        except ValueError:
            counts['malformed_receipt'] += 1
            continue
        if not isinstance(native, dict):
            counts['malformed_receipt'] += 1
            continue
        valid = (native.get('contract') == 'corelink-staging-d1-binding-runtime-v1' and
                 native.get('outcome') == 'pass' and native.get('probe_nonce') == NONCE and
                 native.get('worker_release') == RELEASE and native.get('old_probe_release') == OLD_RELEASE and
                 type(native.get('scheduled_time_ms')) is int and
                 START <= native['scheduled_time_ms'] <= END and
                 all(native.get(key) is True for key in NATIVE_CHECKS))
        if valid:
            # Allowlisted values only; never retain arbitrary log fields/payloads.
            receipts.append({'contract': native['contract'], 'outcome': 'pass',
                'probe_nonce': NONCE, 'worker_release': RELEASE, 'old_probe_release': OLD_RELEASE,
                'scheduled_time_ms': native['scheduled_time_ms'],
                **{key: True for key in NATIVE_CHECKS}, 'event_sha256': digest(event)})
        else:
            counts['rejected_receipt'] += 1
    return {'classification': 'historical_native_receipt_recovered' if receipts else
            'historical_attempt_failed_or_claimed' if failed else 'no_conclusive_historical_evidence',
            'event_count': len(events), 'limit_reached': len(events) == 100,
            'filter_counts': counts, 'tail_close_provenance': 'not_available_in_this_query_contract',
            'failed_marker_count': failed, 'historical_receipts': receipts}


def collect(call=request):
    out = {'contract': 'issue1700-historical-classification-v1', 'run_id': '36775268954',
           'dry': True, 'new_runtime_proof': False, 'query_sha256': digest(QUERY),
           'timeframe': QUERY['timeframe'], 'classification': 'unknown'}
    try:
        status, body, _ = call(f'/accounts/{ACCOUNT}')
        out['account_check_http'] = status
        out['account_identity_verified'] = (status == 200 and body.get('success') is True and
                                           body.get('result', {}).get('id') == ACCOUNT)
        if not out['account_identity_verified']:
            out['classification'] = 'account_verification_denied'
            return out
        status, body, response_hash = call(QUERY_PATH, QUERY)
        out.update(query_http=status, response_sha256=response_hash,
            api_error_codes=[e['code'] for e in body.get('errors', [])
                             if isinstance(e, dict) and type(e.get('code')) is int])
        if status in (401, 403):
            out['classification'] = 'historical_query_unauthorized' if status == 401 else 'historical_query_forbidden'
        elif status != 200 or body.get('success') is not True:
            out['classification'] = 'historical_query_rejected'
        else:
            out.update(classify(body))
    except Exception:
        # Exception text, API error messages and source logs can contain secrets.
        out['classification'] = 'bounded_query_error'
    return out


def main():
    if not os.environ.get('EXPECTED_SHA') or os.environ['EXPECTED_SHA'] != os.environ.get('GITHUB_SHA'):
        raise SystemExit('exact workflow SHA required')
    receipt = collect()
    target = Path(os.environ['RUNNER_TEMP']) / 'issue-1700-historical-classification.json'
    target.write_text(json.dumps(receipt, indent=2) + '\n')
    target.chmod(0o600)
    print(json.dumps({'classification': receipt['classification'],
        'new_runtime_proof': False, 'artifact_sha256': hashlib.sha256(target.read_bytes()).hexdigest()}))
    return 0 if receipt['classification'] == 'historical_native_receipt_recovered' else 1


if __name__ == '__main__':
    raise SystemExit(main())
