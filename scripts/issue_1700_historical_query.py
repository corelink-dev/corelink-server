#!/usr/bin/env python3
"""One bounded, dry aggregate query for the exact failed i1700 v8 run."""
import hashlib
import json
import math
import os
from pathlib import Path
import urllib.error
import urllib.request

ACCOUNT = '6a1fc1c626fc2628823e60b9db01f5cd'
BASE = 'https://api.cloudflare.com/client/v4'
QUERY_PATH = f'/accounts/{ACCOUNT}/workers/observability/telemetry/query'
SOURCE_SHA = '7d18bcfc450db97b1b987923050b92971da530a8'
VERSION = '002e974d-4271-4630-9745-96ffbfc83af6'
RUN_ID = '36829094848'
START = 1790839493000  # 2026-10-01T07:24:53Z
END = 1790840995000    # 2026-10-01T07:49:55Z
LIMIT = 100
GROUP_KEYS = ('$metadata.type', '$workers.eventType', '$workers.outcome')
METADATA_TYPES = frozenset(('cf-worker-event', 'cf-worker-log'))
EVENT_TYPES = frozenset((
    'fetch', 'scheduled', 'alarm', 'cron', 'queue', 'email', 'tail',
    'rpc', 'jsrpc', 'websocket', 'workflow', 'unknown',
))
OUTCOMES = frozenset((
    'ok', 'exception', 'exceededCpu', 'exceededMemory', 'scriptNotFound',
    'canceled', 'responseStreamDisconnected', 'unknown',
))
QUERY = {
    'queryId': 'issue1700-run36829094848-v8-outcome-counts',
    'dry': True,
    'view': 'calculations',
    'chartType': 'aggregate',
    'ignoreSeries': True,
    'limit': LIMIT,
    'timeframe': {'from': START, 'to': END},
    'parameters': {
        'filterCombination': 'and',
        'filters': [
            {'key': '$metadata.service', 'operation': 'eq', 'type': 'string', 'value': 'corelink-staging'},
            {'key': '$workers.scriptVersion.id', 'operation': 'eq', 'type': 'string',
             'value': VERSION},
        ],
        'calculations': [{'operator': 'count', 'alias': 'event_count'}],
        'groupBys': [{'type': 'string', 'value': key} for key in GROUP_KEYS],
    },
}
EXPECTED_QUERY_SHA256 = '5a11a2113fdc085b497bbe943bf5e2a8c6bf9722d132b6ebe9bb3f3706ff1150'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def request(path, body):
    """Perform exactly one fixed POST; never follow redirects or retry."""
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
        if response.status != 200:
            return response.status, None
        try:
            return response.status, json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError('response_invalid') from None


def _bucket(value, allowed):
    if not isinstance(value, str):
        return 'unknown'
    return value if value in allowed else 'other'


def _group_key(aggregate):
    groups = aggregate.get('groups')
    if not isinstance(groups, list):
        raise ValueError('aggregate_groups')
    values = {}
    for item in groups:
        if not isinstance(item, dict) or not isinstance(item.get('key'), str):
            raise ValueError('aggregate_group_entry')
        key = item['key']
        if key not in GROUP_KEYS or key in values:
            raise ValueError('aggregate_group_key')
        values[key] = item.get('value')
    return '|'.join((
        _bucket(values.get('$metadata.type'), METADATA_TYPES),
        _bucket(values.get('$workers.eventType'), EVENT_TYPES),
        _bucket(values.get('$workers.outcome'), OUTCOMES),
    ))


def classify(body):
    if not isinstance(body, dict) or body.get('success') is not True:
        raise ValueError('response_envelope')
    result = body.get('result')
    if not isinstance(result, dict):
        raise ValueError('response_result')
    run = result.get('run')
    if not isinstance(run, dict):
        raise ValueError('response_run')
    account_confirmed = run.get('accountId') == ACCOUNT
    dry_confirmed = run.get('dry') is True
    status = run.get('status')
    if status not in ('STARTED', 'COMPLETED'):
        raise ValueError('run_status')
    if not account_confirmed:
        classification = 'account_mismatch'
    elif not dry_confirmed:
        classification = 'dry_not_confirmed'
    elif status != 'COMPLETED':
        classification = 'query_run_incomplete'
    else:
        calculations = result.get('calculations')
        if not isinstance(calculations, list):
            raise ValueError('calculations_envelope')
        matches = [row for row in calculations if isinstance(row, dict) and row.get('alias') == 'event_count']
        if len(matches) != 1 or not isinstance(matches[0].get('aggregates'), list):
            raise ValueError('aggregate_envelope')
        aggregates = matches[0]['aggregates']
        if len(aggregates) > LIMIT:
            raise ValueError('aggregate_limit')
        statistics = result.get('statistics', {})
        if not isinstance(statistics, dict):
            raise ValueError('statistics_envelope')
        abr_level = statistics.get('abr_level', 1)
        if type(abr_level) not in (int, float) or not math.isfinite(abr_level) or abr_level <= 0:
            raise ValueError('abr_level')
        sampling_uncertain = abr_level != 1
        counts = {}
        for aggregate in aggregates:
            if not isinstance(aggregate, dict):
                raise ValueError('aggregate_entry')
            count = aggregate.get('count')
            sample_interval = aggregate.get('sampleInterval')
            if (type(count) not in (int, float) or not math.isfinite(count) or count < 0 or
                    type(sample_interval) not in (int, float) or not math.isfinite(sample_interval) or
                    sample_interval <= 0):
                raise ValueError('aggregate_count')
            if sample_interval != 1:
                sampling_uncertain = True
            key = _group_key(aggregate)
            total = counts.get(key, 0) + count
            if not math.isfinite(total):
                raise ValueError('aggregate_count')
            counts[key] = total
        scheduled_invocations = sum(
            count for key, count in counts.items()
            if key.split('|')[0] == 'cf-worker-event' and key.split('|')[1] in ('scheduled', 'cron')
        )
        log_records = sum(count for key, count in counts.items() if key.split('|')[0] == 'cf-worker-log')
        if len(aggregates) == LIMIT:
            classification = 'aggregate_limit_reached'
        elif sampling_uncertain:
            classification = 'sampling_uncertain'
        elif scheduled_invocations > 0:
            classification = 'scheduled_invocations_observed'
        elif log_records > 0:
            classification = 'logs_observed_no_scheduled_group'
        elif aggregates:
            classification = 'candidate_groups_without_scheduled_invocation'
        else:
            classification = 'no_groups_returned'
        return {
            'classification': classification,
            'account_confirmed': account_confirmed,
            'dry_confirmed': dry_confirmed,
            'query_status': status,
            'sampling': 'uncertain' if sampling_uncertain else 'exact',
            'abr_level': abr_level,
            'groups_returned': len(aggregates),
            'group_limit_reached': len(aggregates) == LIMIT,
            'counts': counts,
            'scheduled_invocation_count': scheduled_invocations,
            'log_record_count': log_records,
            'new_runtime_proof': False,
        }
    return {
        'classification': classification,
        'account_confirmed': account_confirmed,
        'dry_confirmed': dry_confirmed,
        'query_status': status,
        'sampling': 'unknown',
        'groups_returned': 0,
        'group_limit_reached': False,
        'counts': {},
        'scheduled_invocation_count': 0,
        'log_record_count': 0,
        'new_runtime_proof': False,
    }


def collect(call=request):
    receipt = {
        'contract': 'issue1700-v8-aggregate-diagnostic-v1',
        'run_id': RUN_ID,
        'candidate_source_sha': SOURCE_SHA,
        'candidate_version_id': VERSION,
        'timeframe': QUERY['timeframe'],
        'query_sha256': digest(QUERY),
        'classification': 'unknown',
        'new_runtime_proof': False,
    }
    try:
        if receipt['query_sha256'] != EXPECTED_QUERY_SHA256:
            raise ValueError('request_hash_mismatch')
        status, body = call(QUERY_PATH, QUERY)
        receipt['query_http'] = status
        if status == 401:
            receipt['classification'] = 'query_unauthorized'
        elif status == 403:
            receipt['classification'] = 'query_forbidden'
        elif status == 400:
            receipt['classification'] = 'query_bad_request'
        elif status == 429:
            receipt['classification'] = 'query_rate_limited'
        elif 300 <= status < 400:
            receipt['classification'] = 'query_redirect_rejected'
        elif 500 <= status < 600:
            receipt['classification'] = 'query_server_error'
        elif status != 200:
            receipt['classification'] = 'query_rejected'
        else:
            receipt.update(classify(body))
    except Exception as error:
        code = str(error) if str(error) in {
            'request_not_allowlisted', 'token_unavailable', 'response_bound', 'response_invalid',
            'request_hash_mismatch', 'response_envelope', 'response_result', 'response_run',
            'run_status', 'calculations_envelope', 'aggregate_envelope', 'aggregate_limit',
            'statistics_envelope', 'abr_level', 'aggregate_entry', 'aggregate_count',
            'aggregate_groups', 'aggregate_group_entry', 'aggregate_group_key',
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
        'classification', 'query_http', 'sampling', 'groups_returned',
        'group_limit_reached', 'counts', 'scheduled_invocation_count',
        'log_record_count', 'new_runtime_proof',
    ) if key in receipt}, sort_keys=True))
    complete_classes = {
        'scheduled_invocations_observed', 'logs_observed_no_scheduled_group',
        'candidate_groups_without_scheduled_invocation', 'no_groups_returned',
    }
    return 0 if (receipt.get('query_http') == 200 and receipt.get('account_confirmed') and
                 receipt.get('dry_confirmed') and receipt.get('query_status') == 'COMPLETED' and
                 receipt.get('sampling') == 'exact' and
                 not receipt.get('group_limit_reached') and
                 receipt.get('classification') in complete_classes) else 1


if __name__ == '__main__':
    raise SystemExit(main())
