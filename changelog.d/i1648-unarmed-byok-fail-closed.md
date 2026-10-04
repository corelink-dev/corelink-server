### Security

- **A no-provider container refuses every tenant whose BYOK state is not
  `inactive`.** Before, a binary with no KMS provider attached no BYOK data
  plane, so a tenant that was `active`, `partial`, `shredded` or `pending` would
  have been written and read in plaintext. Such rows could only come from an
  armed era; production has none. The container now holds a config view. On
  first use it reads every `tenant_byok_config` row that is not `inactive`,
  including a NULL state. It refuses those tenants fail-closed on CAS and AC
  reads, existence probes, lists, deletes and writes, and before any byte
  reservation. CAS and AC lists check the shared unarmed config snapshot
  before R2 enumeration, including when no runtime gate is attached. Engaged
  tenants and config-source failures receive a refusal with zero R2 dispatch;
  object identifiers, sizes and timestamps are never returned on that path.
  A row it cannot parse refuses its own tenant. A row without a tenant id
  refuses every tenant. All
  other tenants keep the plaintext path, with no D1 read per request and no D1
  dependency at boot. A failed load is retried on the next request, not cached.

  Verifiers B-083, B-087 and B-154, the weekly BYOK matrix static check, and
  the CAIQ, SIG-LITE and owner-action packets now describe the no-provider
  build. Every 501 activation claim must give its cause, and the old
  "if provider construction or CMK access fails" wording is rejected.
