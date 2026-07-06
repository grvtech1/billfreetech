# BillFree TechSupport Ops — API Contract (Source of Truth)

> Verified against **production** `_live/Code.js` (7,854 lines) and `_live/Index.html`
> (byte-identical to the working-dir `Index.html`), cloned via clasp on 2026-07-06.
> Script ID: `1B2-DDjd8MgXrIe-Yye3Zik4sT66uakP4MmmD_bKAPZiwUYoYWtdxscmG`.
>
> The working-dir `Code.gs` (3,452-line "split") is **abandoned scratch, never deployed** —
> do not treat it as the backend. Refactor base = `_live/Code.js`.

The backend is reachable **two ways**, and most functions serve both:

1. **`google.script.run.<fn>(...)`** — from the embedded `Index.html` (GAS HtmlService).
2. **`doPost(e)` JSON actions** — from the React SPA / Cloudflare shell.

Line numbers below are in `_live/Code.js` unless noted.

---

## 1. Client-callable functions (`google.script.run`)

All **client-facing** functions return a **`JSON.stringify(...)` string**; the frontend parses it.
Envelope in practice: `{ success: boolean, ... }` on success, `{ success: false, error: "[Exxx] message" }` on failure.

| Fn | Line | Args (order) | Returns (success) | Auth |
|---|---|---|---|---|
| `getCurrentUserEmail` | (auth blk) | `token` | `{success,email,agentName,name,role,isAdmin,source}` | verifies token |
| `getCSRFToken` | (auth blk) | — | `{success,token}` | none (issues token) |
| `checkVersion` | (platform) | — | `{success,version}` | none |
| `getTicketData` | 3141 | `idToken` *(vestigial, unused)* | `{success,tickets[],directory,version,cacheStatus}` | **none** (documented) |
| `getTicketsPaginated` | 4467 | `config{page,pageSize,filters,sort,idToken}` | `{success,data[],pagination,version,sort}` | `requirePermission('VIEW_ANALYTICS')` |
| `getDashboardStats` | 4560 | `config{idToken,dateFrom,dateTo}` | `{success,kpi,agents[],totalTickets,version}` | `requirePermission('VIEW_ANALYTICS')` |
| `updateTicketPOS` | 3272 | `ticketId,newPos,csrfToken,idToken` | `{success,message,ticketId,pos,version}` | identity+CSRF+`UPDATE_TICKET`+ratelimit |
| `updateTicketStatus` | 3382 | `ticketId,newStatus,csrfToken,idToken` | `{success,message,ticketId,newStatus}` | identity+CSRF+`UPDATE_TICKET`+ratelimit |
| `appendTicketReason` | 3496 | `ticketId,newReason,csrfToken,idToken` | `{success,message,ticketId}` | identity+CSRF+`UPDATE_TICKET`+ratelimit |
| `updateTicketFull` | 3607 | `ticketId,newStatus,newReason,csrfToken,idToken` | `{success,message,ticketId,newStatus}` | CSRF+ratelimit+`UPDATE_TICKET` |
| `createNewTicket` | 3743 | `ticketData,csrfToken,idToken` | `{success,ticketId,message}` | identity+CSRF+ratelimit **(no `requirePermission`)** |
| `exportTicketsToCSV` | (export) | `options{idToken,csrfToken,...}` | `{success,data,rowCount,headers}` | `EXPORT_TICKETS`+CSRF |
| `exportReportAsCSV` | 2560 | `config{idToken,csrfToken,month,year}` | `{success,csv,filename}` | `EXPORT_REPORT`+CSRF |
| `exportHistoryToCSV` | (export) | `config{csrfToken,filters}` | `{success,csv,data,rowCount,filename}` | `EXPORT_HISTORY`(no idToken)+CSRF |
| `getUpdateHistory` | 5098 | `config{page,pageSize,filters,idToken}` | `{success,data[],pagination,durationStats}` | **none** (documented) |
| `generateMonthlyReport` | (report) | `{month,year}` | `{success,report}` | none |
| `sendMonthlyReportEmail` | (report) | `{month,year,csrfToken}` | `{success,message}` | CSRF |
| `generateMonthlyNarrativeServer` | (report) | `report,csrfToken` | `{success,html}` | CSRF |
| `aiAnalytics` | 7524 | `intent,payload,csrfToken` | `{success,data,cached,tokenIn,tokenOut}` | CSRF+ratelimit **(no `requirePermission`)** |
| `getAgentList` | (platform) | — | `[agents]` / `{agents}` | none |

### ⚠️ NOT client API — do not "normalize" their return type

These return **raw JS values** (not JSON strings). They are unused-from-client and/or **internal helpers** — changing their return type breaks internal callers:

| Fn | Line | Returns | Why raw is correct |
|---|---|---|---|
| `getDataObjects` | 3018 | raw array | not called from FE or doPost |
| `getFeatureFlag` | 4893 | raw scalar | **called internally** (e.g. `MAX_EXPORT_ROWS`) — must stay raw |
| `getAuditLogStats` | 2083 | raw object | admin/debug helper, not client API |
| `getAllFeatureFlags` | 4945 | JSON string | `requirePermission('MANAGE_USERS')`, **no CSRF** |
| `getSystemHealth` | 4753 | JSON string | **no auth** — leaks row counts / data version |

---

## 2. `doPost(e)` action table (SPA / Cloudflare path)

Actions are **lowercased** before matching (line 2827). `payload.token` → `idToken`.

| action | → function |
|---|---|
| `portal_create` | `portalCreateTicket` |
| `portal_lookup` | `portalLookupTicket` |
| `createticket` | `api_createTicket_` |
| `getticketdata` | `getTicketData(token)` |
| `getcsrftoken` | `getCSRFToken()` |
| `updateticketfull` | `updateTicketFull(id,status,reason,csrf,token)` |
| `updateticketstatus` | `updateTicketStatus(id,status,csrf,token)` |
| `updateticketpos` | `updateTicketPOS(id,pos‖newPos,csrf,token)` |
| `appendreason` | `appendTicketReason(id,reason‖newReason,csrf,token)` |
| `createticketauth` | `createNewTicket(data‖payload,csrf,token)` |
| `getanalytics` (sub) | `getTopMIDsSameConcern` / `…DifferentConcerns` / `getTopPOS` / `getRepeatCustomerAnalysis` / `getConcernTrendAnalysis` / `getAgentSpecializationMatrix` |
| `getcallhistory` | `getCallHistory` |
| `logcallevent` | `logCallEvent` |
| `getmonthlyreport` | `generateMonthlyReport` |
| `getupdatehistory` | `getUpdateHistory` |
| `exporttickets` | `exportTicketsToCSV` |
| `provider_cdr` (default) | webhook-secret → `ingestProviderCdrEvent_` |
| unknown | `{success:false, error:'[VALIDATION_FAILED] Unsupported action'}` |

> `aiAnalytics`, `exportReportAsCSV`, `getDashboardStats` are **NOT** in doPost — `google.script.run` only.

---

## 3. Frontend consumption (`Index.html`) — conventions & inconsistencies

- **`scriptRun(method,args,opts)`** wrapper (line 8529) — parses, checks `.success`, toasts, rejects on failure. **Defined but never used** (all 22 call sites use raw `google.script.run`).
- **`aiCallServer(intent,payload)`** (line 17857) — a second wrapper for `aiAnalytics` that **resolves `{success:false}` on failure** (opposite of `scriptRun`, which rejects).
- **JSON.parse discipline**: 7 sites use **strict `JSON.parse(res)`** (throws if backend ever returns a non-string): `getCSRFToken` (8817), `updateTicketFull` (12775), `createNewTicket` (13189), `getUpdateHistory` (15452), `generateMonthlyNarrativeServer` (17314, 17396), `aiAnalytics` (17876). The rest use guarded `typeof res==='string' ? JSON.parse : res`.
- **CSRF passed 3 ways**: positional arg (`updateTicketPOS/Full`, `createNewTicket`, `generateMonthlyNarrativeServer`, `aiAnalytics`) · inside payload object (`exportHistoryToCSV`, `sendMonthlyReportEmail`, `exportReportAsCSV`) · not at all (reads).
- **Identity**: server-injected `%%INJECT_*%%` tokens at render (primary) + `postMessage` from Cloudflare parent + `getCurrentUserEmail` verify. **No `fetch()` in Index.html** — the "CF proxy" is an iframe host, not an HTTP proxy from this file.
- **Duplicate call sites**: `getCurrentUserEmail` (123 & 18953), `getAgentList` (19134 & 19163).

---

## 4. Confirmed defects (verified in production)

| # | Defect | Location | Severity | Contract-safe fix? |
|---|---|---|---|---|
| D1 | CSRF compare uses `!==`, **not** constant-time, despite comment; `secureEquals_` exists (1888) & is used for webhook/API-key but **not CSRF** | `validateCSRFTokenEnhanced` 795–797 | **High (security)** | ✅ yes — swap in `secureEquals_` |
| D2 | `exportReportAsCSV` returns **raw object** on inner-fail (2567) vs **JSON string** on success (2600) | 2567 | Med | ✅ yes — stringify the fail path |
| D3 | `getSystemHealth` has **no auth**, leaks internal metadata | 4753 | Med (security) | ✅ yes — gate behind admin |
| D4 | `getAllFeatureFlags` has no CSRF (read of privileged config) | 4945 | Low | ✅ yes |
| D5 | `apiError()` structured envelope defined but **never called**; real fns return `{error:"[Exxx] text"}` | 607 | Low (consistency) | ⚠️ envelope change — needs FE co-change |
| D6 | 7 FE sites use fragile strict `JSON.parse`; `scriptRun()` wrapper is dead; `aiCallServer` has opposite failure semantics | Index.html (see §3) | Low→Med | ✅ yes — route through `scriptRun()` |
| D7 | `createNewTicket` / `aiAnalytics` have no `requirePermission` gate (rely on CSRF+identity only) | 3743 / 7524 | Low (by-design?) | ⚠️ confirm intent before changing |

**Not defects (intentional):** no-auth on `getTicketData` & `getUpdateHistory` (documented — "Anyone" deployment + Google URL access control); raw returns on `getFeatureFlag` (internal helper).
