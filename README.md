# C129 — mscalendar: renew wipes webhook ClientState → forged webhook + OAuth token SSRF

**Status:** CONFIRMED (synthetic local) — NOT submitted  
**Platform / program:** Bugcrowd — Mattermost Public Bug Bounty (`mattermost-mbb-public`)  
**Asset:** https://github.com/mattermost/mattermost-plugin-mscalendar (in-scope OSS plugin)  
**Reviewed at:** `c79b1c661b292fcc91bc339e1b30343ede34b767` (2026-10-30)  
**Severity (VRT):** High (P2) — Improper Authorization / Missing Authentication on webhook after renew; chains to OAuth bearer exfil via absolute `resource` URL  
**CWE:** CWE-863, CWE-306, CWE-918  
**Novelty:** Not CVE-2026-10556 (nil webhook DoS). ClientState added in PR #40 / issue #13 but renew path never merges prior secret. No public advisory for renew wipe + Resource SSRF.

## Sibling-endpoint gap (create vs renew)

| Path | Code | ClientState behavior |
|------|------|----------------------|
| **Create** `CreateMySubscription` | `msgraph/subscription.go` | Sets `ClientState: newRandomString()`, POSTs into **same** `*sub`. Graph omit leaves field intact (Go `json.Unmarshal` preserves). |
| **Renew** `RenewSubscription` | same file | PATCH into **fresh** `remote.Subscription{}`. Response typically omits/nulls `clientState` → stored secret becomes `""`. |
| **Gate** `processNotification` | `calendar/engine/notification.go:132-133` | `if sub.Remote.ClientState != "" && sub.Remote.ClientState != n.ClientState` — **empty stored secret skips auth entirely**. |
| **Fetch** `GetNotificationData` | `msgraph/get_notification_data.go` | `CallJSON(GET, wh.Resource, …)` — `Resource` from webhook body (attacker-controlled once gate skipped). |
| **HTTP** `call.go` + `remote.go` | | Absolute URL used as-is; `httpClient` is `oauth2.NewClient` → `Authorization: Bearer <victim>` sent to attacker host. |

Natural trigger: calendar subscriptions TTL 48h; `RecommendRenew` when within 12h of expiry (`handle_webhook.go`). First near-expiry MS webhook renews and **persists wiped ClientState**; all later webhooks (including forged) skip the secret check. Functional calendar notifications keep working (gate only fails closed when secret non-empty).

## Preconditions / impact

1. Victim has connected MS Calendar (subscription exists).  
2. At least one renew cycle has run (automatic).  
3. Attacker knows `subscriptionId` (GUID). Sources: prior observed MS→plugin webhook on path, debug logs (`subscriptionID`), plugin KV / admin. Not user-enumerable via normal REST in this review.  
4. Attacker POSTs to public plugin notification URL with victim `subscriptionId`, arbitrary `clientState`, and `resource: "https://attacker/collect"` with `@odata.type: "#Microsoft.Graph.Event"`.  
5. Plugin loads victim OAuth token and GETs attacker URL → **token theft**. Relative Graph paths also force victim-token Graph calls under attacker path control.

## Synthetic PoC

```bash
cd poc/r33-c129-mscalendar-clientstate-wipe && go test -v .
```

Proves: create-omit preserves secret; renew-omit/null wipes; empty gate accepts any ClientState; absolute Resource bypasses Graph base join.

## Fix (advisory only — do not PR)

On renew, merge `renewed.ClientState = oldSub.ClientState` (or reject empty stored ClientState). Reject absolute URLs in `GetNotificationData` / `call` (allowlist Graph host + relative paths). Prefer fail-closed: `if sub.Remote.ClientState == "" || sub.Remote.ClientState != n.ClientState`.

## Out of scope for this package

No production testing, no customer data, no Bugcrowd submission in this round.
