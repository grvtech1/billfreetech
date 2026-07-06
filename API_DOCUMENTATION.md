# BillFree — Ticket Creation API (WhatsApp / Chatbot)

**Version:** v1.1 | **Updated:** 2026-07-06 | **Contact:** gaurav.pal@billfree.in

A single synchronous endpoint to create a support ticket. Designed for WhatsApp AI
chatbots and other automated integrations. The ticket is created and an agent is
auto-assigned in the same request; the result is returned in the response body.
**No webhooks, no polling.**

---

## Endpoint

```
POST https://script.google.com/macros/s/AKfycbxWiztHE-FDLLxheZLC8dgv9e095GqB5sYkluREN7sPrbl88BZZLaQWVsVk58VCRqTG/exec
```

- **Content-Type:** `application/json`
- **Redirects:** Google Apps Script issues one 302 redirect. Your client **must follow redirects** (`-L` in cURL, `allow_redirects=True` in Python, `redirect: "follow"` in fetch). The final response body is JSON.

---

## Authentication

Every request must include an `apiKey` field. Keys are issued by BillFree and are
tied to a name and a per-key rate limit. Treat the key as a secret.

```json
{ "apiKey": "bf_wa_live_xxxxxxxx" }
```

> The example key above is a **placeholder**. Use the real key BillFree provisions for you.

---

## Request

```json
{
  "action": "createTicket",
  "apiKey": "bf_wa_live_xxxxxxxx",
  "concern": "POS machine not responding",
  "phone": "9876543210",
  "requestedBy": "Customer Name",
  "business": "ABC Store",
  "mid": "123456",
  "pos": "Terminal-01"
}
```

| Field | Required | Description |
|---|:---:|---|
| `action` | ✅ | Must be `"createTicket"` (case-insensitive) |
| `apiKey` | ✅ | API key provided by BillFree |
| `concern` | ✅ | Issue description (max 500 chars). **The only content field that is mandatory.** |
| `phone` | ➖ Recommended | Customer phone (digits; used for duplicate protection). Strongly recommended for WhatsApp. |
| `requestedBy` | ⬜ Optional | Customer name. Default: `"WhatsApp User"` |
| `business` | ⬜ Optional | Business name (max 200). Default: `"-"` |
| `mid` | ⬜ Optional | Merchant ID (digits only; non-digits stripped). Blank if omitted. |
| `pos` | ⬜ Optional | POS terminal ID (max 50). Default: `"-"` |

> **Minimal valid request:** `action`, `apiKey`, `concern`. Everything else is optional —
> ideal for a chatbot that only captured the customer's issue and phone number.

---

## Response

### Success — `200`, `success: true`

```json
{
  "success": true,
  "data": {
    "ticketId": "BF-TKT-2026-07-2526",
    "assignedAgent": "Agent Name",
    "status": "Not Completed",
    "requestId": "req_abc123def45"
  }
}
```

### Error — `success: false`

```json
{
  "success": false,
  "error": "Human-readable error message",
  "code": "E004",
  "requestId": "req_abc123def45"
}
```

| Code | Meaning | Retry? |
|---|---|---|
| `E001` | Rate limit **or** duplicate request | Wait 60s (rate) / see *Duplicate handling* (dup) |
| `E002` | Invalid, missing, or deactivated API key | Fix the key |
| `E004` | Validation error (e.g. missing `concern`) | Fix the request |
| `E005` | Ticket database temporarily unavailable | Retry after a few seconds |
| `E006` | Server busy (lock contention) | Retry after ~5s |
| `E999` | Internal error | Contact BillFree with the `requestId` |

---

## Duplicate handling (idempotency)

To protect against WhatsApp message re-sends, the same **`phone` + `concern`** (first 50
characters, case-insensitive) is de-duplicated for **5 minutes**. A repeat within that
window returns `E001` **and includes the already-created ticket id** so you can reassure
the user instead of showing a failure:

```json
{
  "success": false,
  "error": "Duplicate request. A ticket with this phone and concern was created in the last 5 minutes.",
  "code": "E001",
  "requestId": "req_...",
  "data": { "existingTicketId": "BF-TKT-2026-07-2526" }
}
```

**Recommended chatbot handling:** if `code === "E001"` and `data.existingTicketId` is
present, treat it as success and reply with that ticket id.

---

## WhatsApp response mapping

**New ticket (`success: true`):**
> *"✅ Your ticket **{{data.ticketId}}** has been created. Our agent **{{data.assignedAgent}}** will contact you shortly."*

**Duplicate (`code: "E001"` with `data.existingTicketId`):**
> *"You already have an open ticket **{{data.existingTicketId}}** for this. Our team is on it."*

**Other failure:**
> *"Sorry, we couldn't create your ticket right now. Please try again in a moment."*

---

## Rate limits

- **Per API key:** 60 requests/minute by default (configurable per key), 60-second sliding window. Exceeding it returns `E001`.
- **Duplicate protection:** same `phone` + `concern` blocked for 5 minutes (see above).

---

## Behaviour notes

1. **Agent assignment is automatic** — round-robin across active, non-admin agents, with load-balancing that skips any agent carrying a heavy backlog. You do not choose the agent.
2. **Ticket IDs are globally sequential** — format `BF-TKT-YYYY-MM-XXXX`. The number never resets; only the `YYYY-MM` label changes month to month.
3. **New tickets always start as `"Not Completed"`** — status is server-controlled.
4. **All times are IST** (UTC+5:30).
5. **Save the `requestId`** from every response — include it when reporting issues to BillFree.

---

## Examples

### cURL
```bash
curl -L -X POST \
  "https://script.google.com/macros/s/AKfycbxWiztHE-FDLLxheZLC8dgv9e095GqB5sYkluREN7sPrbl88BZZLaQWVsVk58VCRqTG/exec" \
  -H "Content-Type: application/json" \
  -d '{"action":"createTicket","apiKey":"bf_wa_live_xxxxxxxx","concern":"POS not working","phone":"9876543210"}'
```

### Python
```python
import requests

resp = requests.post(
    "https://script.google.com/macros/s/AKfycbxWiztHE-FDLLxheZLC8dgv9e095GqB5sYkluREN7sPrbl88BZZLaQWVsVk58VCRqTG/exec",
    json={
        "action": "createTicket",
        "apiKey": "bf_wa_live_xxxxxxxx",
        "concern": "POS not working",
        "phone": "9876543210"
    },
    allow_redirects=True,
    timeout=20,
)
data = resp.json()
if data.get("success"):
    print("Ticket:", data["data"]["ticketId"])
elif data.get("code") == "E001" and data.get("data", {}).get("existingTicketId"):
    print("Existing ticket:", data["data"]["existingTicketId"])
else:
    print("Error:", data.get("error"))
```

### JavaScript (Node.js)
```javascript
const resp = await fetch(
  "https://script.google.com/macros/s/AKfycbxWiztHE-FDLLxheZLC8dgv9e095GqB5sYkluREN7sPrbl88BZZLaQWVsVk58VCRqTG/exec",
  {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      action: "createTicket",
      apiKey: "bf_wa_live_xxxxxxxx",
      concern: "POS not working",
      phone: "9876543210"
    }),
    redirect: "follow"
  }
);
const data = await resp.json();
if (data.success) {
  console.log("Ticket:", data.data.ticketId);
} else if (data.code === "E001" && data.data?.existingTicketId) {
  console.log("Existing ticket:", data.data.existingTicketId);
} else {
  console.error("Error:", data.error);
}
```
