#!/usr/bin/env python3
"""Do not restore pre-retirement Worker code while a probe trigger/tail remains."""
import json
import os
from pathlib import Path
import urllib.request

API = 'https://api.cloudflare.com/client/v4/accounts/6a1fc1c626fc2628823e60b9db01f5cd/workers/scripts/corelink-staging'


def read(path):
    if path not in ('/schedules', '/tails'):
        raise ValueError('unapproved read')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    request = urllib.request.Request(API + path, headers={
        'Authorization': 'Bearer ' + os.environ['WORKER_API_TOKEN']})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        raw = response.read(65537)
        if response.status != 200 or len(raw) > 65536:
            raise ValueError('bounded read failed')
        return json.loads(raw)


def inspect(read_api=read):
    receipt = {'contract': 'issue1700-preimage-rollback-quiescence-v1',
               'rollback_allowed': False, 'rollback_attempted': False,
               'schedules_empty': False, 'tails_empty': False}
    try:
        schedules = read_api('/schedules')
        tails = read_api('/tails')
        if (schedules.get('success') is not True or tails.get('success') is not True or
            not isinstance(schedules.get('result'), dict) or
            not isinstance(schedules['result'].get('schedules'), list) or
            not isinstance(tails.get('result'), list)):
            raise ValueError('inventory envelope rejected')
        receipt['schedules_empty'] = schedules['result']['schedules'] == []
        receipt['tails_empty'] = tails['result'] == []
        receipt['rollback_allowed'] = receipt['schedules_empty'] and receipt['tails_empty']
        receipt['reason'] = 'quiescent' if receipt['rollback_allowed'] else 'probe_activity_remains'
    except Exception:
        receipt['reason'] = 'quiescence_unproven'
    return receipt


def main():
    receipt = inspect()
    receipt["rollback_attempted"] = os.environ.get("ROLLBACK_CONTAINER_RESTORE_ATTEMPTED") == "1"
    receipt["preimage_worker_restore_attempted"] = False
    path = Path(os.environ['RUNNER_TEMP']) / 'staging-rollback-quiescence.json'
    path.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))
    return 0 if receipt['rollback_allowed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
