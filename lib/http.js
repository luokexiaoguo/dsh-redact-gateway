/**
 * The settings page's HTTP surface.
 *
 * These are `exact` routes on the bare web server, which means the harness's own
 * `/api` fence never sees them: this module has to decide for itself whether a
 * request may read the gateway's state or export its audit log. It therefore
 * asks the connection service and, for mutations, additionally requires a
 * same-origin browser request — the loopback `Host` check is what stops a DNS
 * rebinding page from driving it.
 *
 * @module dsh-redact-gateway/http
 */

import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

/** Route prefix owned by this plugin. */
export const ROUTE_PREFIX = '/dsh-redact-gateway';

/** Maximum accepted JSON body for the mutating routes. */
const MAX_BODY_BYTES = 64 * 1024;

/**
 * Write a JSON response.
 * @param res - the server response.
 * @param status - HTTP status.
 * @param payload - JSON-serializable body.
 */
function sendJson(res, status, payload) {
  res.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
  });
  res.end(JSON.stringify(payload));
}

/**
 * Whether a `Host` header names a loopback authority.
 * @param host - the request's Host header.
 */
function loopbackAuthority(host) {
  if (typeof host !== 'string') return false;
  const lower = host.toLowerCase();
  const name = lower.startsWith('[') ? lower.slice(0, lower.indexOf(']') + 1) : lower.split(':')[0];
  return name === '127.0.0.1' || name === 'localhost' || name === '[::1]';
}

/**
 * Same-origin check for a mutating request.
 *
 * An absent `Origin` is allowed: browsers always send it on POST, so its absence
 * means the caller is not a page — and the Desktop build's proxy strips it.
 * @param req - the incoming request.
 */
function sameOrigin(req) {
  if (req.headers['sec-fetch-site'] === 'cross-site') return false;
  const origin = req.headers.origin;
  if (origin === undefined) return true;
  try {
    const originUrl = new URL(origin);
    const host = req.headers.host;
    if (typeof host !== 'string') return false;
    if (originUrl.host === host) return true;
    // Chrome 151+ omits the port on a loopback Origin.
    if (originUrl.port === '' && loopbackAuthority(host)) {
      const hostName = host.toLowerCase().startsWith('[')
        ? host.slice(0, host.indexOf(']') + 1)
        : host.split(':')[0];
      return originUrl.hostname === hostName;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Decide whether a request may reach the plugin's routes.
 * @param ctx - plugin context (for the optional connection service).
 * @param req - the incoming request.
 * @returns `undefined` when admitted, or the status to answer with.
 */
function admissionStatus(ctx, req) {
  const connection = ctx.get('connection');
  if (connection !== undefined && typeof connection.requestRejection === 'function') {
    try {
      const status = connection.requestRejection({ headers: req.headers });
      if (status !== undefined) return status;
    } catch {
      // A gate that throws admitted nothing; failing open here would turn a
      // harness bug into the exposure this exists to close.
      return 403;
    }
    return undefined;
  }
  // No connection service: only a loopback authority may speak to us.
  return loopbackAuthority(req.headers.host) ? undefined : 403;
}

/**
 * Read a size-capped JSON body.
 * @param req - the incoming request.
 * @returns the parsed body.
 */
async function readJsonBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_BODY_BYTES) throw new Error('request body too large');
    chunks.push(buffer);
  }
  if (size === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

/** Send one structured failure. */
function sendError(res, status, message) {
  sendJson(res, status, { ok: false, error: message });
}

/**
 * Register the plugin's routes on the web server.
 * @param ctx - plugin context.
 * @param gateway - the gateway state source.
 * @param options.warn - diagnostic sink.
 * @returns a disposer, or `undefined` when the host has no web server.
 */
export function registerRoutes(ctx, gateway, { warn }) {
  const server = ctx.get('webServer');
  if (server === undefined || typeof server.register !== 'function') return undefined;

  const handlers = [
    [
      `${ROUTE_PREFIX}/state`,
      async (req, res) => {
        if (req.method !== 'GET') return sendError(res, 405, 'GET only');
        sendJson(res, 200, { ok: true, ...gateway.state() });
      },
    ],
    [
      `${ROUTE_PREFIX}/audit`,
      async (req, res) => {
        if (req.method !== 'GET') return sendError(res, 405, 'GET only');
        const url = new URL(req.url ?? '/', 'http://localhost');
        const limit = clampNumber(url.searchParams.get('limit'), 50, 1, 500);
        const since = parseTime(url.searchParams.get('since'));
        const category = url.searchParams.get('category') ?? undefined;
        const rows = gateway.audit.query({ limit, since, category });
        sendJson(res, 200, { ok: true, rows });
      },
    ],
    [
      `${ROUTE_PREFIX}/config`,
      async (req, res) => {
        if (req.method !== 'POST') return sendError(res, 405, 'POST only');
        if (!sameOrigin(req)) return sendError(res, 403, 'cross-origin request refused');
        const body = await readJsonBody(req);
        if (body.paused === true) {
          gateway.pause(clampNumber(body.minutes, 30, 1, 24 * 60) * 60 * 1000);
          return sendJson(res, 200, { ok: true, ...gateway.state() });
        }
        if (body.paused === false) gateway.resume();
        const result = gateway.applyConfig(body);
        sendJson(res, 200, { ok: true, applied: result.applied, persisted: result.persisted, ...gateway.state() });
      },
    ],
    [
      `${ROUTE_PREFIX}/export`,
      async (req, res) => {
        if (req.method !== 'POST') return sendError(res, 405, 'POST only');
        if (!sameOrigin(req)) return sendError(res, 403, 'cross-origin request refused');
        const body = await readJsonBody(req);
        const since = parseTime(body.since);
        const until = parseTime(body.until);
        const category = typeof body.category === 'string' && body.category.length > 0 ? body.category : undefined;
        const exportsDir = join(gateway.paths.root, 'exports');
        if (!existsSync(exportsDir)) mkdirSync(exportsDir, { recursive: true, mode: 0o700 });
        const stamp = new Date().toISOString().replace(/[:.]/g, '-');
        const outPath = join(exportsDir, `redact-audit-${stamp}.csv`);
        const result = gateway.audit.exportCsv({ since, until, category }, outPath);
        const filename = outPath.slice(outPath.lastIndexOf('\\') + 1);
        // Very large exports are written to disk only; the page then shows the path.
        const inline = result.rows <= 20000 ? result.csv : '';
        sendJson(res, 200, {
          ok: true,
          path: result.path,
          filename,
          rows: result.rows,
          csv: inline,
        });
      },
    ],
  ];

  const disposers = [];
  for (const [path, handler] of handlers) {
    const dispose = server.register({
      kind: 'exact',
      path,
      handler: async (req, res) => {
        const status = admissionStatus(ctx, req);
        if (status !== undefined) {
          return sendJson(res, status, {
            ok: false,
            error:
              status === 401
                ? '需要重新打开 DSH Web 的启动网址完成登录。 / DSH login required: reopen the URL dsh web printed at startup.'
                : '请求来自不受信任的来源，已拒绝。 / Untrusted origin refused.',
          });
        }
        try {
          await handler(req, res);
        } catch (error) {
          warn(`route ${path} failed: ${error instanceof Error ? error.message : String(error)}`);
          if (!res.headersSent) sendError(res, 400, 'request failed');
          else res.end();
        }
      },
    });
    disposers.push(dispose);
  }

  return () => {
    for (const dispose of disposers) {
      try {
        dispose();
      } catch {
        /* the server is already gone */
      }
    }
  };
}

/** Parse a millisecond timestamp from a query/body value. */
function parseTime(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.length > 0) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return numeric;
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

/** Clamp a query/body number into range. */
function clampNumber(value, fallback, min, max) {
  const numeric = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(numeric)));
}
