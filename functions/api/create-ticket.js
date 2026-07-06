/**
 * Cloudflare Pages Function — BillFree Ticket Creation Proxy
 * ----------------------------------------------------------
 * Purpose: give the WhatsApp chatbot provider a DIRECT JSON API.
 *
 * Google Apps Script /exec ALWAYS answers a POST with a 302 redirect to
 * script.googleusercontent.com, where the real JSON body is served. Many HTTP
 * clients (and webhook platforms) don't want to follow that. This function
 * follows the redirect server-side (Cloudflare's fetch does it automatically)
 * and returns the final JSON straight back with a clean HTTP 200 — no redirect
 * ever reaches the caller.
 *
 * Deployed at:  https://<your-pages-domain>/api/create-ticket
 * Method:       POST  (application/json)
 * Body:         forwarded VERBATIM to the GAS Ticket API (see API_DOCUMENTATION.md)
 * Response:     the GAS JSON body, unchanged, HTTP 200
 *
 * The GAS URL can be overridden without a code change via the Pages env var
 * GAS_TICKET_API_URL (Cloudflare dashboard → Settings → Environment variables).
 */

// Fallback target = the "Final WA API Working" deployment of the GAS project.
// Prefer setting GAS_TICKET_API_URL in the Pages project env instead of editing this.
const DEFAULT_GAS_URL =
  'https://script.google.com/macros/s/AKfycbxWiztHE-FDLLxheZLC8dgv9e095GqB5sYkluREN7sPrbl88BZZLaQWVsVk58VCRqTG/exec';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

function jsonResponse(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...CORS_HEADERS,
    },
  });
}

/** POST — forward to GAS, return the final JSON directly (no 302). */
export async function onRequestPost({ request, env }) {
  const target = (env && env.GAS_TICKET_API_URL) || DEFAULT_GAS_URL;

  // Read the incoming body verbatim (do not re-serialize — pass through as sent).
  let bodyText = '';
  try {
    bodyText = await request.text();
  } catch (e) {
    return jsonResponse(
      { success: false, error: 'Could not read request body', code: 'E004' },
      400
    );
  }

  // Forward to GAS. Cloudflare's fetch follows the 302 → googleusercontent hop
  // automatically (redirect: 'follow' is the default) and yields the final JSON.
  let upstreamText;
  try {
    const upstream = await fetch(target, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: bodyText,
      redirect: 'follow',
    });
    upstreamText = await upstream.text();
  } catch (e) {
    return jsonResponse(
      { success: false, error: 'Upstream request failed: ' + (e && e.message), code: 'E999' },
      502
    );
  }

  // Guard: GAS should return JSON. If it returned an HTML error/login page
  // instead (deploy misconfig, access wall), surface a clean error rather than
  // leaking Google's HTML to the provider.
  try {
    JSON.parse(upstreamText);
  } catch (e) {
    return jsonResponse(
      {
        success: false,
        error: 'Upstream returned a non-JSON response (check the GAS deployment URL and its access = "Anyone").',
        code: 'E999',
      },
      502
    );
  }

  // Return the GAS JSON body exactly as-is, with a clean 200.
  return new Response(upstreamText, {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...CORS_HEADERS,
    },
  });
}

/** CORS preflight. */
export function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

/**
 * GET → helpful JSON hint (so a browser hit doesn't look broken).
 * NOTE: do NOT export a generic `onRequest` here — in Pages Functions it would
 * override onRequestPost/onRequestOptions and break the proxy. Other methods
 * (PUT/DELETE/…) are auto-answered with 405 by the Pages runtime.
 */
export function onRequestGet() {
  return jsonResponse(
    { success: false, error: 'Use POST with application/json to create a ticket.', code: 'E004' },
    405
  );
}
