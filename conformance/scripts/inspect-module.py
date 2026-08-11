#!/usr/bin/env python3
"""Fetch a running/waiting test module's info + log via the Conformance API, without a browser.

Usage:
    CONFORMANCE_TOKEN=<token> [CONFORMANCE_SERVER=https://demo.certification.openid.net] \
        conformance/scripts/inspect-module.py <module_id>

<module_id> is printed by run-test-plan.py as part of "Created test module, new id: <module_id>"
and the accompanying "<server>log-detail.html?log=<module_id>" line while a run is in progress.

Prints the module's current status, then scans its log for entries that look like a
redirect/browser-visit instruction (keys like redirect_to/url/location, or an INFO-level
condition result), followed by the full raw log as JSON for anything the heuristic misses.
"""
import asyncio
import json
import os
import sys

from conformance import Conformance


async def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    module_id = sys.argv[1]

    api_url_base = os.environ.get('CONFORMANCE_SERVER', 'https://demo.certification.openid.net')
    token = os.environ.get('CONFORMANCE_TOKEN')
    if not token:
        print('CONFORMANCE_TOKEN is not set.', file=sys.stderr)
        sys.exit(1)

    conformance = Conformance(api_url_base, token, verify_ssl=True)
    try:
        info = await conformance.get_module_info(module_id)
        print('=== status ===')
        print(json.dumps({k: info.get(k) for k in ('status', 'result', 'testName') if k in info}, indent=2))

        log = await conformance.get_test_log(module_id)

        print('\n=== entries that look like a redirect/browser-visit instruction ===')
        found_any = False
        for entry in log:
            haystack = json.dumps(entry)
            if any(key in entry for key in ('redirect_to', 'url', 'location', 'authorization_endpoint')) \
                    or 'browser' in haystack.lower() or 'PLACEHOLDER' in haystack:
                found_any = True
                print(json.dumps(entry, indent=2))
        if not found_any:
            print('(none matched the heuristic -- see the full log below)')

        print('\n=== full raw log ({} entries) ==='.format(len(log)))
        print(json.dumps(log, indent=2))
    finally:
        await conformance.close_client()


if __name__ == '__main__':
    asyncio.run(main())
