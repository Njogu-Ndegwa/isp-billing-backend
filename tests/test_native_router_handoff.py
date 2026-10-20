import asyncio
import hashlib
import time
from copy import deepcopy

import pytest
from unittest.mock import AsyncMock

from app.services import native_router_stream as stream
from app.services.native_router_api import NativeApiError
from app.services.native_router_handoff import guard_marker, validate_handoff
from app.services.native_router_lease import lease_sources


class RouterState:
    """Only the native operations used by reporter ownership; names are unique."""
    failure = None

    def __init__(self):
        self.info = {"id": 563, "identity": "Router-test"}
        self.source = ':local tok "' + stream.derive_router_token(self.info['identity']) + '"'
        self.digest = hashlib.sha256(self.source.encode()).hexdigest()
        self.timers = {"*1": {".id": "*1", "name": stream.REPORTER, "disabled": "true", "interval": "1m", "on-event": "/system script run bitwave-usage-push"}}
        self.scripts = {"*2": {".id": "*2", "name": stream.REPORTER, "source": self.source}}
        self.leases, self.calls, self.serial = {}, [], 10

    async def rpc(self, path, args=None, query=()):
        await asyncio.sleep(0)
        args = dict(args or {})
        self.calls.append((path, args))
        if path == '/system/identity/print':
            return {"rows": [{"name": self.info['identity']}]}
        if path == '/system/resource/print':
            return {"rows": [{"board-name": "RB951Ui-2HnD", "version": "7.24.2"}]}
        if path == '/interface/print':
            return {"rows": [{".id": "*3", "name": "ether1"}]}
        if path == '/ip/route/print':
            return {"rows": [{"dst-address": "0.0.0.0/0", "active": "true", "immediate-gw": "192.0.2.1%ether1"}]}
        collections = {
            '/system/script': self.scripts, '/system/scheduler': self.timers,
            '/ip/firewall/address-list': self.leases,
        }
        base, operation = path.rsplit('/', 1)
        items = collections[base]
        if operation == 'print':
            rows = list(items.values())
            for word in query:
                key, value = word[1:].split('=', 1)
                rows = [row for row in rows if row.get(key) == value]
            return {'rows': deepcopy(rows)}
        if operation == 'add':
            if base == '/system/script' and any(r['name'] == args['name'] for r in items.values()):
                raise NativeApiError('Native request rejected')
            self.serial += 1
            identifier = '*' + format(self.serial, 'X')
            items[identifier] = {'.id': identifier, **args}
            if base == '/ip/firewall/address-list':
                items[identifier]['dynamic'] = 'true'
            return {'done': {'ret': identifier}, 'rows': []}
        if operation == 'set':
            items[args['.id']].update({k: v for k, v in args.items() if k != '.id'})
        elif operation == 'remove':
            del items[args['.id']]
        else:
            raise AssertionError(path)
        return {'done': {}, 'rows': []}

    def owner(self):
        session = stream.StreamSession(self.info, self.digest, self)
        session.original = {**self.timers['*1'], 'disabled': 'false'}
        session.cfg = {**lease_sources(563, '1m'), 'owner': session.owner}
        session.guard_created = session.claimed = True
        session.last_accepted = time.monotonic()
        self.timers['*4'] = {
            '.id': '*4', 'name': session.cfg['name'], 'disabled': 'false',
            'on-event': session.cfg['guard'], 'comment': session.guard_comment,
        }
        self.leases['*5'] = {
            '.id': '*5', 'list': session.cfg['list'], 'address': '127.255.0.1',
            'dynamic': 'true', 'comment': 'Bitwave native API RAM lease:' + session.owner,
        }
        return session


@pytest.mark.asyncio
async def test_clean_handoff_keeps_reporter_paused_and_transfers_lease_before_retiring_old(monkeypatch):
    monkeypatch.setattr(stream.settings, 'NATIVE_STREAM_GRACEFUL_HANDOFF', True)
    api = RouterState()
    old = api.owner()
    await old.handoff()
    assert guard_marker(api.timers['*4']['comment'])['handoff']
    await old.release()
    assert api.timers['*1']['disabled'] == 'true'
    new = stream.StreamSession(api.info, api.digest, api)
    await new.preflight()
    assert new.original['disabled'] == 'false'
    before = len(api.calls)
    await new.claim()
    new.last_accepted = time.monotonic()
    calls = api.calls[before:]
    add = next(i for i, (p, _) in enumerate(calls) if p == '/ip/firewall/address-list/add')
    remove = next(i for i, (p, _) in enumerate(calls) if p == '/ip/firewall/address-list/remove')
    assert add < remove
    assert api.timers['*1']['disabled'] == 'true'
    assert api.timers['*4']['comment'] == new.guard_comment
    assert all(r['comment'].endswith(new.owner) for r in api.leases.values())
    assert not any(r['name'].startswith('bw-native-api-claim-') for r in api.scripts.values())
    assert not any(p == '/system/scheduler/set' and 'disabled' in a for p, a in calls)
    await old.release()
    assert api.timers['*4']['comment'] == new.guard_comment


@pytest.mark.asyncio
async def test_only_one_simultaneous_successor_can_claim_the_handoff(monkeypatch):
    monkeypatch.setattr(stream.settings, 'NATIVE_STREAM_GRACEFUL_HANDOFF', True)
    api = RouterState()
    await api.owner().handoff()
    successors = [stream.StreamSession(api.info, api.digest, api) for _ in range(2)]
    for session in successors:
        await session.preflight()
    results = await asyncio.gather(*(s.claim() for s in successors), return_exceptions=True)
    assert sum(not isinstance(r, BaseException) for r in results) == 1
    winner = next(s for s in successors if s.claimed)
    loser = next(s for s in successors if not s.claimed)
    await loser.release()
    assert api.timers['*1']['disabled'] == 'true'
    assert api.timers['*4']['comment'] == winner.guard_comment
    assert all(r['comment'].endswith(winner.owner) for r in api.leases.values())


@pytest.mark.asyncio
@pytest.mark.parametrize('age', [None, 121])
async def test_stale_or_missing_ingestion_acknowledgement_cannot_extend_the_guard(age):
    api = RouterState()
    owner = api.owner()
    owner.last_accepted = None if age is None else time.monotonic() - age
    before = len(api.calls)
    with pytest.raises(RuntimeError, match='acknowledgement'):
        await owner.handoff()
    assert api.calls[before:] == []
    assert not owner.handed_off


@pytest.mark.asyncio
async def test_changed_handoff_after_preflight_is_not_adopted(monkeypatch):
    monkeypatch.setattr(stream.settings, 'NATIVE_STREAM_GRACEFUL_HANDOFF', True)
    api = RouterState()
    await api.owner().handoff()
    session = stream.StreamSession(api.info, api.digest, api)
    await session.preflight()
    api.timers['*4']['comment'] = 'changed by operator'
    with pytest.raises(RuntimeError, match='handover'):
        await session.claim()
    assert not session.claimed
    assert api.timers['*1']['disabled'] == 'true'
    assert api.timers['*4']['comment'] == 'changed by operator'
    assert not any(r['name'].startswith('bw-native-api-claim-') for r in api.scripts.values())


@pytest.mark.asyncio
async def test_manually_paused_reporter_without_handoff_stays_paused(monkeypatch):
    monkeypatch.setattr(stream.settings, 'NATIVE_STREAM_GRACEFUL_HANDOFF', True)
    api = RouterState()
    api.owner()
    session = stream.StreamSession(api.info, api.digest, api)
    before = len(api.calls)
    with pytest.raises(RuntimeError, match='handover'):
        await session.preflight()
    assert not any(p.endswith(('/set', '/add', '/remove')) for p, _ in api.calls[before:])
    assert api.timers['*1']['disabled'] == 'true'


@pytest.mark.parametrize('change', ['expired', 'future', 'source', 'owner', 'static', 'missing', 'reporter_event'])
def test_handoff_validation_refuses_untrusted_or_expired_state(change):
    api = RouterState()
    owner = api.owner()
    guard = api.timers['*4']
    guard['comment'] = stream.GUARD_COMMENT + ':handoff:' + str(int(time.time())) + ':' + owner.owner
    leases = list(api.leases.values())
    if change in ('expired', 'future'):
        offset = -121 if change == 'expired' else 60
        guard['comment'] = stream.GUARD_COMMENT + ':handoff:' + str(int(time.time()) + offset) + ':' + owner.owner
    elif change == 'source':
        guard['on-event'] = 'modified'
    elif change == 'owner':
        leases[0]['comment'] = 'another owner'
    elif change == 'static':
        leases[0]['dynamic'] = 'false'
    elif change == 'reporter_event':
        api.timers['*1']['on-event'] = 'different-script'
    else:
        leases = []
    with pytest.raises(RuntimeError):
        validate_handoff(guard, api.timers['*1'], owner.cfg, leases)


@pytest.mark.asyncio
@pytest.mark.parametrize('shutdown,cancelled', [(True, True), (False, True), (True, False)])
async def test_only_clean_shutdown_cancellation_uses_handoff(monkeypatch, shutdown, cancelled):
    monkeypatch.setattr(stream.settings, 'NATIVE_STREAM_GRACEFUL_HANDOFF', True)
    monkeypatch.setattr(stream, '_stopping', shutdown)
    api, session, tables = AsyncMock(), AsyncMock(), AsyncMock()
    session.preflight.return_value = 'ether1'
    tables.bootstrap.side_effect = asyncio.CancelledError() if cancelled else RuntimeError('counter failure')
    monkeypatch.setattr(stream, 'load_router', AsyncMock(return_value={
        'id': 563, 'identity': 'Router-test', 'ip_address': '10.0.0.217',
        'username': 'test', 'password': 'test', 'port': 8728,
    }))
    monkeypatch.setattr(stream, 'AsyncNativeAPI', lambda *args: api)
    monkeypatch.setattr(stream, 'StreamSession', lambda *args: session)
    monkeypatch.setattr(stream, 'NativeTables', lambda *args, **kwargs: tables)
    with pytest.raises(asyncio.CancelledError if cancelled else RuntimeError):
        await stream.stream_router(563, 'a' * 64)
    if shutdown and cancelled:
        session.handoff.assert_awaited_once()
        session.release.assert_not_awaited()
    else:
        session.release.assert_awaited_once()
        session.handoff.assert_not_awaited()
    api.close.assert_awaited_once()
