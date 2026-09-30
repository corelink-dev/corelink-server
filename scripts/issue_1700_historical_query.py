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
START, END = 1790727123000, 1790728458000  # 2026-09-30 00:12:03..00:34:18 UTC
VERSION = '516d7e11-c366-4ebf-b84b-eec9a4861446'
RELEASE = '0f785fb9b096afe01247f1057d46377b9f604f13'
NONCE = 'issue-1700-recovery-20260929'
NATIVE_CHECKS = ('parameterized_select', 'failed_batch_observed', 'rollback_absence_verified',
                 'probe_table_dropped', 'd1_binding_intercepted', 'authorization_absent', 'cf_api_token_absent')
QUERY = {
    'queryId': 'issue1700-run36649066490-readonly', 'dry': True, 'view': 'events', 'limit': 100,
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
    for event in events:
        workers = event.get('$workers', {})
        if (workers.get('scriptName') != 'corelink-staging' or
            workers.get('scriptVersion', {}).get('id') != VERSION or
            workers.get('eventType') not in ('scheduled', 'cron') or
            type(event.get('timestamp')) is not int or not START <= event['timestamp'] <= END):
            continue
        message = event.get('$metadata', {}).get('message', '')
        if message == '[staging_d1_runtime_probe] failed reason=probe_failed':
            failed += 1
        prefix = '[staging_d1_runtime_probe] receipt='
        if not isinstance(message, str) or not message.startswith(prefix):
            continue
        try:
            native = json.loads(message[len(prefix):])
        except ValueError:
            continue
        if not isinstance(native, dict):
            continue
        valid = (native.get('contract') == 'corelink-staging-d1-binding-runtime-v1' and
                 native.get('outcome') == 'pass' and native.get('probe_nonce') == NONCE and
                 native.get('worker_release') == RELEASE and
                 type(native.get('scheduled_time_ms')) is int and
                 START <= native['scheduled_time_ms'] <= END and
                 all(native.get(key) is True for key in NATIVE_CHECKS))
        if valid:
            # Allowlisted values only; never retain arbitrary log fields/payloads.
            receipts.append({'contract': native['contract'], 'outcome': 'pass',
                'probe_nonce': NONCE, 'worker_release': RELEASE,
                'scheduled_time_ms': native['scheduled_time_ms'],
                **{key: True for key in NATIVE_CHECKS}, 'event_sha256': digest(event)})
    return {'classification': 'historical_native_receipt_recovered' if receipts else
            'historical_attempt_failed_or_claimed' if failed else 'no_conclusive_historical_evidence',
            'event_count': len(events), 'limit_reached': len(events) == 100,
            'failed_marker_count': failed, 'historical_receipts': receipts}


def collect(call=request):
    out = {'contract': 'issue1700-historical-classification-v1', 'run_id': '36649066490',
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
