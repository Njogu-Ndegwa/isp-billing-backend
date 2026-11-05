// Public reads share the backend hostname already allowed by hotspot routers.
// New uploads use the c/ prefix. Keys made before 4 Nov 2026 start with ads/,
// and EasyList (Adblock Plus, uBlock, AdGuard, Brave) blocks every image whose
// URL contains "/media/ads/", which hid uploaded photos in the dashboard and
// on portals. So /media/c/<path> serves c/<path> and falls back to the old
// ads/<path> object (the backend rewrites old links to /media/c/), and
// /media/ads/ keeps working for anything still holding an old link.
const MEDIA_PATH = /^\/media\/(ads|c)\/(\d{4}\/\d{2}\/[A-Za-z0-9_-]+\.(?:webp|jpg|png|mp4))$/;
const MIME = { webp: 'image/webp', jpg: 'image/jpeg', png: 'image/png', mp4: 'video/mp4' };

export default {
  async fetch(request, env) {
    if (!['GET', 'HEAD'].includes(request.method)) {
      return new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, HEAD' } });
    }
    const match = MEDIA_PATH.exec(new URL(request.url).pathname);
    if (!match) return new Response('Not found', { status: 404 });
    const [, prefix, rest] = match;
    const read = (key) => (request.method === 'HEAD'
      ? env.AD_MEDIA.head(key)
      : env.AD_MEDIA.get(key, { onlyIf: request.headers, range: request.headers }));
    let key = `${prefix}/${rest}`;
    let object = await read(key);
    if (!object && prefix === 'c') {
      key = `ads/${rest}`;
      object = await read(key);
    }
    if (!object) return new Response('Not found', { status: 404 });
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set('Content-Type', MIME[key.split('.').pop()]);
    headers.set('ETag', object.httpEtag);
    headers.set('Last-Modified', object.uploaded.toUTCString());
    headers.set('Accept-Ranges', 'bytes');
    headers.set('Cache-Control', 'public, max-age=86400');
    headers.set('X-Content-Type-Options', 'nosniff');
    // These are public ad assets, including draft previews in the dashboard.
    headers.set('Access-Control-Allow-Origin', '*');
    if (request.method === 'GET' && !('body' in object)) {
      const precondition = request.headers.has('If-Match') || request.headers.has('If-Unmodified-Since');
      return new Response(null, { status: precondition ? 412 : 304, headers });
    }
    let status = 200;
    const range = request.method === 'GET' && request.headers.has('Range') && object.range;
    if (range) {
      const offset = range.offset ?? Math.max(0, object.size - range.suffix);
      const length = range.length ?? Math.min(range.suffix, object.size);
      headers.set('Content-Range', `bytes ${offset}-${offset + length - 1}/${object.size}`);
      headers.set('Content-Length', String(length));
      status = 206;
    } else {
      headers.set('Content-Length', String(object.size));
    }
    return new Response(request.method === 'HEAD' ? null : object.body, { status, headers });
  },
};
