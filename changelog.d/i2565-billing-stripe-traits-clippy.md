### Fixed

- **The billing Stripe traits crate passes `clippy -D warnings` again (#2565).** `DurableWebhookInbox::reserve_effect_with_context` and `commit_effect_with_context` took eight arguments, which failed `clippy::too_many_arguments` in the billing campaign lane. They now take one `InboxEffect` value plus the request context. The dispatcher builds that value once, so reserve and commit always use the same effect identity. The unused `emit_audit_and_sli` helper in `corelink-stripe-real`, the next `-D warnings` error in the same lane, is removed.
