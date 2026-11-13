import assert from 'node:assert/strict';
import test from 'node:test';
import worker from './worker.mjs';

const url = 'https://isp.bitwavetechnologies.com/media/ads/2026/11/r12-abc123.jpg';
const makeObject = (extra = {}) => ({
  body: 'photo', size: 5, httpEtag: '"etag"', uploaded: new Date('2026-11-01T12:00:00Z'),
  writeHttpMetadata(headers) { headers.set('Content-Type', 'text/html'); }, ...extra,
});
const env = (object) => ({ AD_MEDIA: { async get() { return object; }, async head() { return object; } } });

test('serves media with enforced image type and public caching', async () => {
  const response = await worker.fetch(new Request(url), env(makeObject()));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'image/jpeg');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(await response.text(), 'photo');
});
test('HEAD exposes size without retrieving the body', async () => {
  let got = false;
  const response = await worker.fetch(new Request(url, { method: 'HEAD' }), { AD_MEDIA: {
    async head() { return makeObject(); }, async get() { got = true; },
  } });
  assert.equal(got, false);
  assert.equal(response.headers.get('content-length'), '5');
  assert.equal(await response.text(), '');
});
test('supports a video range response', async () => {
  const response = await worker.fetch(new Request(url.replace('.jpg', '.mp4'), { headers: { Range: 'bytes=1-3' } }), env(makeObject({ body: 'hot', range: { offset: 1, length: 3 } })));
  assert.equal(response.status, 206);
  assert.equal(response.headers.get('content-range'), 'bytes 1-3/5');
  assert.equal(await response.text(), 'hot');
});
test('returns 304 when R2 conditional read has no body', async () => {
  const object = makeObject(); delete object.body;
  const response = await worker.fetch(new Request(url, { headers: { 'If-None-Match': '"etag"' } }), env(object));
  assert.equal(response.status, 304);
});
test('rejects public writes and paths outside generated ad keys', async () => {
  assert.equal((await worker.fetch(new Request(url, { method: 'PUT', body: 'x' }), env(null))).status, 405);
  for (const path of ['/api/ads', '/media/private/key.jpg', '/media/ads/2026/11/file.html', '/media/ads/2026/11/%2e%2e%2fprivate.jpg']) {
    assert.equal((await worker.fetch(new Request(new URL(path, url)), env(null))).status, 404);
  }
});
test('serves the ad-blocker-safe /media/c/ path, falling back to the old ads/ key', async () => {
  const stored = { 'c/2026/11/r12-new.jpg': makeObject(), 'ads/2026/11/r12-old.jpg': makeObject() };
  const asked = [];
  const bucket = { AD_MEDIA: {
    async get(key) { asked.push(key); return stored[key] ?? null; },
    async head(key) { asked.push(key); return stored[key] ?? null; },
  } };
  const at = (path, init) => worker.fetch(new Request(`https://isp.bitwavetechnologies.com${path}`, init), bucket);
  assert.equal((await at('/media/c/2026/11/r12-new.jpg')).status, 200);
  assert.equal((await at('/media/c/2026/11/r12-old.jpg')).headers.get('content-type'), 'image/jpeg');
  assert.equal((await at('/media/ads/2026/11/r12-old.jpg', { method: 'HEAD' })).status, 200);
  assert.equal((await at('/media/c/2026/11/r12-none.jpg')).status, 404);
  assert.deepEqual(asked, [
    'c/2026/11/r12-new.jpg',
    'c/2026/11/r12-old.jpg', 'ads/2026/11/r12-old.jpg',
    'ads/2026/11/r12-old.jpg',
    'c/2026/11/r12-none.jpg', 'ads/2026/11/r12-none.jpg',
  ]);
  for (const path of ['/media/c/x.jpg', '/media/c/2026/11/a.html', '/media/m/2026/11/a.jpg']) {
    assert.equal((await at(path)).status, 404);
  }
});
test('missing object returns 404', async () => {
  assert.equal((await worker.fetch(new Request(url), env(null))).status, 404);
});
