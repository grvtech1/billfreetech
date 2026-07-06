# Ticket Creation API Proxy (no-302)

Gives integrators a **direct JSON API** for ticket creation — no Google Apps Script
302 redirect to handle.

- **File:** `functions/api/create-ticket.js` (Cloudflare Pages Function)
- **Public URL (after deploy):** `https://billfreetech.pages.dev/api/create-ticket`
- **Method:** `POST` · `Content-Type: application/json`
- **Behaviour:** forwards the body verbatim to the GAS Ticket API, follows the 302
  server-side, and returns the final JSON with a clean **HTTP 200**. Request/response
  contract is identical to [../API_DOCUMENTATION.md](../API_DOCUMENTATION.md) — only the
  URL changes and there is no redirect.

## Deploy

Cloudflare Pages picks up the `functions/` directory automatically.

- **Direct Upload:** re-upload the whole `cloudflare-pages/` folder (incl. `functions/`)
  to the `billfreetech` Pages project. The function goes live at `/api/create-ticket`.
- **Git-connected:** push; Pages builds and deploys the function.

### Optional: point at a different GAS deployment without editing code
Cloudflare dashboard → the Pages project → **Settings → Environment variables** →
add `GAS_TICKET_API_URL` = the GAS `/exec` URL. The function prefers it over the
hardcoded fallback.

## Test (after deploy)

```bash
# New ticket — expect {"success":true,"data":{"ticketId":"BF-TKT-..."}} with HTTP 200, no redirect
curl -i -X POST "https://billfreetech.pages.dev/api/create-ticket" \
  -H "Content-Type: application/json" \
  -d '{"action":"createTicket","apiKey":"<REAL_KEY>","concern":"proxy smoke test","phone":"9999999999"}'

# Re-send within 5 min — expect {"success":false,"code":"E001","data":{"existingTicketId":"BF-TKT-..."}}
```

Confirm the response has **no `Location:` header** and status **200** — that's the whole point.

## Notes

- The proxy is transparent: authentication (`apiKey`), rate limiting, validation and
  duplicate handling all still happen in the GAS backend.
- If the proxy ever returns `502` with *"Upstream returned a non-JSON response"*, the
  GAS deployment URL is wrong or its access isn't set to **"Anyone"**.
- CORS is open (`*`) so browser-based callers work too; server-to-server callers are unaffected.
