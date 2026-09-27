# B-216 provider-neutral DSR DLQ critical-alert contract

## Purpose and boundary

The signup worker sends one critical notification for an exhausted DSR DLQ event to an explicitly configured owner-approved HTTPS sink. This is a transport contract only. It does not select a vendor, prove that a human received the notification, or authorize a live queue exercise. A provider-specific route is never the default.

The contract follows the repo-owned `AlertTransport` and `DeliveryReceipt` pattern: an endpoint must be configured, delivery returns an explicit receipt only after acceptance, and missing configuration, rejected status, or transport failure never count as success.

## Request

The worker sends an HTTPS `POST` with `Content-Type: application/json` and a `Bearer` authorization token. Redirects are rejected. The endpoint and token are separate Worker secrets and must be selected/provisioned through the approved release process.

The JSON object is closed and contains exactly these fields:

```json
{
  "schema_version": 1,
  "event": "dsr.erasure.dead_letter",
  "severity": "critical",
  "component": "dsr-erasure-dlq",
  "event_id": "dsr-erasure-dlq:<64 lowercase hex characters>",
  "exhausted": true,
  "requeue_count": 0
}
```

`event_id` is the stable opaque correlation and deduplication key for this queue event. The request must never include a queue body, DSR/tenant/subject identity, salt, user identifier, or secret. A sink may add vendor-specific fields only inside its own adapter, after accepting this closed CoreLink envelope.

## Acceptance and errors

- Any HTTP 2xx response is an explicit acceptance receipt, matching the repository's generic `HttpAlertTransport` contract. The Worker creates `DeliveryReceipt { eventId, acceptedAtMs, statusCode }` only from such a response.
- A missing endpoint or token is `not_configured`; malformed or non-HTTPS endpoints are `invalid_endpoint`; non-2xx is `http_rejected`; fetch exceptions are `transport_error`.
- The Worker ignores response bodies and exception details. It does not log the endpoint, token, or raw provider response.
- Rejected, unconfigured, and invalid-endpoint outcomes retain/retry the DLQ copy within its existing bound. An ambiguous transport result is durably marked ambiguous and fenced from another send. The existing receipt, one-time redrive, identity, and legal-hold invariants remain in force.
- A 2xx receipt proves that the configured sink accepted the request. It does not prove on-call reachability or human receipt. Those require separate owner evidence tied to the same opaque event ID.

## Runtime owner boundary

The staging quarantine deployment may omit the endpoint and token while the sink is explicitly deferred. In that state the Worker keeps the existing `not_configured` fail-closed outcome: it creates no alert receipt, makes no network call, and retains the DLQ copy under its existing bounded recovery rules. A release owner must select an approved sink, provision its endpoint and dedicated token through protected secret storage, and record the configured response path before enabling a controlled exhausted-message operation. Operations must separately prove the delivery reached that response path. Deployment, sink selection/provisioning, migrations, and the controlled exhausted-message operation remain outside the repository contract PR.
