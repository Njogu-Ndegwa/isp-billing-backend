"""Opt-in RouterOS 7 canary. Run inside the production app, one process at a time.

PREAUTH_ROUTER_IDS selects explicitly authorized routers. Install leaves a
30-minute router-local rollback armed. After reviewing the receipt, MODE=keep
removes that timer; MODE=rollback executes its source and verifies removal.
No scripts, payment bindings, queues or existing firewall rules are modified.
"""
import asyncio
import concurrent.futures
import datetime as dt
import json
import os
import statistics
import time

from sqlalchemy import select
from app.db.database import async_session, async_engine
from app.db.models import Router
from app.services.mikrotik_api import MikroTikAPI
from app.services.hotspot_preauth_tls import build_plan, guard_rules, rollback_rsc

IDS = [int(x) for x in os.environ['PREAUTH_ROUTER_IDS'].split(',')]
MODE = os.environ.get('PREAUTH_MODE', 'install')
assert MODE in ('install', 'keep', 'rollback')


def emit(kind, rid, **kw):
    print(json.dumps({'kind': kind, 'router_id': rid, 'utc': dt.datetime.now(dt.timezone.utc).isoformat(), **kw}, default=str), flush=True)


async def load():
    async with async_session() as db:
        rows = (await db.execute(select(Router).where(Router.id.in_(IDS)))).scalars().all()
        data = [(r.id, r.name, (r.ip_address, r.username, r.password, r.port or 8728)) for r in rows]
        await db.commit()
    await async_engine.dispose()
    assert set(x[0] for x in data) == set(IDS)
    return data


def canary(data):
    rid, name, creds = data
    marker = f'bw-preauth-tls-{rid}'
    al = marker + '-portal'
    timer = marker + '-rollback'
    api = MikroTikAPI(*creds, timeout=20, connect_timeout=5)
    assert api.connect(), 'unreachable'

    def read(path, props):
        r = api.send_command_optimized(path, proplist=props)
        assert r.get('success'), path + ': ' + str(r.get('error'))
        return r.get('data', [])

    def cmd(path, args):
        r = api.send_command(path, args)
        assert r.get('success'), path + ': ' + str(r.get('error'))
        return r.get('data', [])

    def snapshot():
        return {
            'monotonic': time.monotonic(),
            'nat': cmd('/ip/firewall/nat/print', {'stats': ''}),
            'filter': cmd('/ip/firewall/filter/print', {'stats': ''}),
            'wan': [x for x in read('/interface/print', ['name', 'rx-byte', 'tx-byte', 'rx-packet', 'tx-packet']) if x.get('name') == 'ether1'],
            'active': read('/ip/hotspot/active/print', ['.id', 'user', 'mac-address', 'address', 'uptime', 'session-time-left']),
            'ppp': read('/ppp/active/print', ['.id', 'service', 'uptime']),
            'queues': read('/queue/simple/print', ['.id', 'name', 'max-limit', 'bytes', 'dynamic', 'disabled']),
            'schedules': read('/system/scheduler/print', ['name', 'disabled', 'run-count', 'interval']),
        }

    def window(label, n):
        before = snapshot()
        start = time.monotonic()
        samples = []
        for i in range(n):
            delay = start + i - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            samples.append(int(read('/system/resource/print', ['cpu-load'])[0]['cpu-load']))
            if i % 30 == 0:
                emit('canary_progress', rid, phase=label, count=len(samples), mean=round(statistics.mean(samples), 2), peak=max(samples))
        after = snapshot()
        emit('canary_window', rid, phase=label, samples=samples, mean=round(statistics.mean(samples), 3), peak=max(samples), samples_ge95=sum(x >= 95 for x in samples), before=before, after=after)
        return samples

    def execute_rollback(source):
        helper = marker + '-undo'
        assert not any(x.get('name') == helper for x in read('/system/script/print', ['name']))
        cmd('/system/script/add', {'name': helper, 'source': source, 'policy': 'read,write,policy,test'})
        try:
            cmd('/system/script/run', {'number': helper})
        finally:
            for x in read('/system/script/print', ['.id', 'name']):
                if x.get('name') == helper:
                    cmd('/system/script/remove', {'.id': x['.id']})

    installed = False
    try:
        resource = read('/system/resource/print', ['board-name', 'version', 'cpu-load'])[0]
        assert resource.get('version', '').startswith('7.'), 'RouterOS 7 canary only'
        timers = [x for x in read('/system/scheduler/print', ['.id', 'name', 'on-event', 'start-date', 'start-time']) if x.get('name') == timer]
        if MODE != 'install':
            assert len(timers) == 1, 'No armed rollback to confirm'
            if MODE == 'rollback':
                execute_rollback(timers[0]['on-event'])
                for path, props in [('/ip/firewall/nat/print', ['comment']), ('/ip/firewall/filter/print', ['comment']), ('/ip/dns/static/print', ['comment']), ('/ip/firewall/address-list/print', ['list'])]:
                    assert not any(marker in str(x) for x in read(path, props)), path
            else:
                assert all(any(x.get('comment') == marker and x.get('disabled') == 'false' for x in read(p, ['comment', 'disabled'])) for p in ['/ip/firewall/nat/print', '/ip/firewall/filter/print'])
                cmd('/system/scheduler/remove', {'.id': timers[0]['.id']})
            emit('canary_' + MODE + '_verified', rid, resource=resource)
            return
        assert not timers, 'Existing canary rollback is still armed'
        for p in ['/ip/firewall/nat/print', '/ip/firewall/filter/print', '/ip/dns/static/print']:
            assert not any(x.get('comment') == marker for x in read(p, ['comment'])), 'Existing managed objects'
        assert not any(x.get('list') == al for x in read('/ip/firewall/address-list/print', ['list'])), 'Existing address list'
        domains = read('/ip/hotspot/walled-garden/print', ['action', 'dst-host', 'dst-address', 'disabled'])
        ips = read('/ip/hotspot/walled-garden/ip/print', ['action', 'dst-host', 'dst-address', 'disabled'])
        existing = read('/ip/dns/static/print', ['name', 'regexp', 'type', 'match-subdomain', 'disabled'])
        plan = build_plan(domains, ips)
        dns = plan.dns_rows(marker=marker, address_list=al, existing=existing)
        addresses = plan.address_rows(marker=marker, address_list=al)
        first = next(x['.id'] for x in read('/ip/firewall/filter/print', ['.id', 'chain']) if x.get('chain') == 'hs-unauth')
        deny, nat = guard_rules(marker=marker, address_list=al, before_filter_id=first)
        emit('canary_preflight_passed', rid, name=name, resource=resource, domains=[x.name for x in plan.domains], lookup_hosts=plan.lookup_hosts, networks=plan.networks)
        window('baseline', 90)
        clock = read('/system/clock/print', ['date', 'time'])[0]
        deadline = dt.datetime.fromisoformat(clock['date'] + 'T' + clock['time']) + dt.timedelta(minutes=30)
        undo = rollback_rsc(marker=marker, address_list=al) + f'\n/system scheduler remove [find where name="{timer}"]'
        cmd('/system/scheduler/add', {'name': timer, 'start-date': deadline.strftime('%Y-%m-%d'), 'start-time': deadline.strftime('%H:%M:%S'), 'interval': '0s', 'on-event': undo, 'policy': 'read,write,policy,test'})
        installed = True
        emit('canary_rollback_armed', rid, router_deadline=deadline.isoformat())
        for row in dns:
            cmd('/ip/dns/static/add', row)
        for row in addresses:
            cmd('/ip/firewall/address-list/add', row)
        # Wait for every concrete hostname to resolve before changing interception.
        time.sleep(5)
        resolved = read('/ip/firewall/address-list/print', ['list', 'address', 'dynamic', 'comment'])
        for host in plan.lookup_hosts:
            assert any(x.get('list') == al and x.get('dynamic') == 'true' and x.get('comment') == host for x in resolved), 'Unresolved portal host: ' + host
        cmd('/ip/firewall/filter/add', deny)
        cmd('/ip/firewall/nat/add', nat)
        # Denial first; removing interception must never create unpaid forwarding.
        for path in ['/ip/firewall/filter', '/ip/firewall/nat']:
            row = next(x for x in read(path + '/print', ['.id', 'comment']) if x.get('comment') == marker)
            cmd(path + '/set', {'.id': row['.id'], 'disabled': 'no'})
        emit('canary_guard_enabled', rid)
        time.sleep(8)
        window('protected', 210)
        emit('canary_observation_complete_rollback_still_armed', rid, router_deadline=deadline.isoformat())
    except Exception as exc:
        emit('canary_error', rid, error=type(exc).__name__ + ': ' + str(exc)[:250])
        if installed:
            try:
                execute_rollback(undo)
                emit('canary_error_rolled_back', rid)
            except Exception as rollback_error:
                emit('canary_rollback_error_timer_retained', rid, error=str(rollback_error)[:200])
        raise
    finally:
        api.disconnect()


if __name__ == '__main__':
    # Router-local streams are sequential. Two independent live canaries share
    # one short-lived app process, with no DB connection held during sampling.
    rows = asyncio.run(load())
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        for result in pool.map(canary, rows):
            pass
