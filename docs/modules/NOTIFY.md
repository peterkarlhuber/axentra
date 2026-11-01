# Notify module

Transactional and product notifications: versioned templates with locale variants, an encrypted
outbox with asynchronous delivery, providers behind one protocol, per-user preferences, a local
development mailbox and delivery statistics. Package `axentra.notify`, HTTP routes in
`axentra.api.routes.notify`, migration `0005_notify.sql`. Module name `notify` (disable it with
`modules = [...]` without `"notify"`; its routes then disappear and invitations send no email).

## Concepts

- **Template** (`tpl_`): per product, unique `key`, `channel` (`email` only; `sms`/`push` are
  reserved for future adapters and rejected with 422), `category`, declared `variables`,
  `sample_data` (for previews), `variants` per locale (`subject`, `text`, optional `html`),
  `sensitive` flag, `version` (optimistic concurrency with `If-Match`). Every template needs an
  `en` variant. **Built-in defaults** live in code (`axentra.notify.builtin`, version 0): currently
  `invitation` (de/en). Creating a template with the same key overrides the default; deleting the
  override restores it.
- **Rendering** (`axentra.notify.render`): only `{{ name }}` placeholders. No expressions,
  filters, attribute access or code execution; anything else starting with `{{` is rejected when
  the template is saved. Templates may only use declared variables. Substitution is single-pass
  (values are never re-expanded). Values in HTML bodies are HTML-escaped; text bodies are not;
  subjects never contain line breaks. A placeholder without a value is a `422 validation_failed`
  with `missing: [...]`. Values must be strings, numbers or booleans (max 10 000 chars, 50 vars).
- **Locale fallback**: requested locale (e.g. `de-at`) -> base language (`de`) -> `en`. The locale
  used is: request `locale` -> the recipient user's locale -> (invitation only) product setting
  `default_locale` -> `en`.
- **Message** (`msg_`, the outbox): product, tenant (nullable for product-level system messages),
  template key and version, category, recipient address (+ `recipient_user_id` when sent to a
  user id), locale, rendered subject/text/html, `status` `queued | sending | sent | failed |
  suppressed`, `attempts`/`max_attempts`, `next_attempt_at`, `last_error` (redacted, max 500
  chars), `provider`, `provider_message_id` (the RFC 5322 Message-ID), `idempotency_key` (unique
  per product).
- **Preferences**: per user and product (`tenant_id = null`) or per user, product and tenant: a list
  of opted-out categories. `transactional` and `security` cannot be opted out (422). Preferences are
  applied **at enqueue time**: the message is stored with status `suppressed` and no content. They
  apply to recipients given by user id and to email recipients whose address belongs to a user.
- **Providers** (`NotificationProvider` protocol: `name`, `send(OutgoingMessage) -> provider id`,
  `check() -> bool`; raise `ProviderError(permanent=...)`):
  - `LocalProvider` (`notify.provider = "local"`, default): never sends; stores what it "delivered"
    in `axentra_notify_mailbox`, readable through the mailbox endpoint. For development and tests.
  - `SmtpProvider` (`"smtp"`): `smtplib`, STARTTLS (`smtp_starttls`, default on; required in
    production unless the host is loopback), certificate verification with the system CAs or
    `smtp_ca_file`, optional AUTH with `smtp_username` + `smtp_password_ref` (`env:`/`file:`).
    5xx replies are permanent failures; 4xx, authentication and connection errors are retried.
  - Custom adapters: `ax.notify.set_provider(obj)`.

## Library usage

```python
ax = Axentra.from_settings(load_settings()); ax.start()
ax.notify.create_template(principal, product_id, key="welcome", category="onboarding",
    variables=["name"], sample_data={"name": "Ada"},
    variants={"en": {"subject": "Welcome {{ name }}", "text": "Hi {{ name }}",
                     "html": "<p>Hi {{ name }}</p>"},
              "de": {"subject": "Willkommen {{ name }}", "text": "Hallo {{ name }}"}})
result = ax.notify.send(principal, product_id, tenant_id, template_key="welcome",
                        to_user_id=user_id, variables={"name": "Ada"}, idempotency_key="signup-42")
# From trusted code (hooks, job handlers) without a permission check:
ax.notify.enqueue_system(product_id, tenant_id, template_key="welcome", to_email="a@example.com",
                         variables={"name": "Ada"})
# Delivery, e.g. from a job worker or cron:
res = ax.notify.dispatcher().run_once(batch=50)   # DispatchResult(claimed, sent, retried, failed, lost)
```

CLI: `axentra notify-dispatch --once [--batch 20]` or `--loop [--interval 2]` (stops on
SIGTERM/SIGINT). `axentra maintenance purge` runs the notify retention (see below).

## HTTP endpoints

All under `/v1/products/{product_id}`; all require authentication.

| Method | Path | Permission | Response |
|---|---|---|---|
| GET | `/notify/templates` | `notify:manage` | `Template[]` (incl. built-ins, `builtin: true`, `id: null`, `version: 0`) |
| POST | `/notify/templates` | `notify:manage` | 201 `Template` |
| POST | `/notify/templates/preview` | `notify:manage` | `RenderedContent` for an unsaved draft `{variables, sample_data, variants, locale, values}` |
| GET | `/notify/templates/{key}` | `notify:manage` | `Template` (+ `ETag`) |
| PATCH | `/notify/templates/{key}` | `notify:manage` | `Template`; `If-Match: <version>` -> 412 on mismatch |
| DELETE | `/notify/templates/{key}` | `notify:manage` | 204; `If-Match` optional |
| POST | `/notify/templates/{key}/preview` | `notify:manage` | `RenderedContent {locale, subject, text, html}`; body `{locale?, variables?}` overrides sample data |
| POST | `/tenants/{tenant_id}/notify/send` | `notify:send` (tenant) | 202 `Message` (200 + `Idempotent-Replayed: true` on replay); body `{template_key, to: {user_id} \| {email}, variables, locale?}`, header `Idempotency-Key` |
| GET | `/notify/messages` | `notify:manage`; or `notify:send` with `tenant_id` | `Page[Message]`; filters `tenant_id, status, template_key, recipient, since`, `limit`, `cursor` |
| GET | `/notify/messages/{id}` | `notify:manage`, or `notify:send` in the message's tenant | `Message` with `content {subject, text, html}` when available |
| POST | `/notify/messages/{id}/retry` | same as GET | `Message` (only `failed` -> `queued`, attempts reset; else 409) |
| GET | `/notify/mailbox` | `notify:manage` | `Page[MailboxEntry {id, message_id, sender, recipient, subject, text, html, provider_message_id, created_at}]`; 409 unless `notify.provider = "local"` |
| GET | `/notify/stats` | `notify:manage` | `DeliveryStats {provider, total{queued,sending,sent,failed,suppressed}, last_24h{...}, oldest_queued_at, attempts_24h}`; optional `tenant_id` |
| GET | `/notify/preferences/me` | user related to the product; with `tenant_id`: `notify:preferences` there | `Preferences {opted_out, available_categories, locked_categories, version}` (+ `ETag`) |
| PUT | `/notify/preferences/me` | as GET | `Preferences`; body `{opted_out: [...]}`, `If-Match` optional (`0` = not yet stored) |

`Message`: `id, product_id, tenant_id, template_key, template_version, channel, category,
recipient, recipient_user_id, locale, status, attempts, max_attempts, next_attempt_at (queued
only), last_error, provider, provider_message_id, idempotency_key, created_by, created_at,
updated_at, sent_at, subject, content_state (available|redacted|purged|none), content`.

Errors: 404 for foreign product/tenant/message (no existence oracle); a user id recipient must be a
member of the tenant or a product operator (else 404, so global users cannot be probed); 409 when an
`Idempotency-Key` is reused with a different request.

## Invitation hook

`Axentra` sets `ax.on_invitation = ax.notify.on_invitation`; the tenancy API calls it after
creating an invitation. It enqueues the `invitation` template (idempotency key
`invitation:<inv_id>`) with `accept_url` = product setting `invitation_accept_url` (http(s) only;
`{token}` is replaced, otherwise `?token=`/`&token=` is appended) or
`<security.public_url>/accept-invitation?token=...`, and sets `accept_url` in the API response.
The hook never raises (the invitation exists either way) and never logs the token or the link.
The built-in invitation template is `sensitive`.

## Guarantees

- Enqueue writes the message and its audit event (`notify.message.enqueue`) in one transaction.
- Idempotency: same `Idempotency-Key` + same request in the same product returns the original
  message, also under concurrent requests (unique index); a different request -> 409.
- Claiming: one `UPDATE ... WHERE id IN (SELECT ... FOR UPDATE SKIP LOCKED)` moves due messages to
  `sending` with a lease (`notify.lease_seconds`) and a per-claim token; concurrent dispatchers never
  claim the same message (tested with threads). Outcomes are written only while the claim token
  matches.
- **At-least-once delivery**: a crash between provider acceptance and the `sent` commit makes the
  lease expire and the message is sent again (the Message-ID header is stable per message
  (`<msg-...@sender-domain>`), so receivers/MTAs can de-duplicate). Not exactly-once.
- Retries: attempt n failing transiently is retried after
  `min(backoff_base_seconds * 2^(n-1), backoff_max_seconds) * (1 + 0..20 % jitter)`; after
  `max_attempts` (default 5), or on a permanent error, the message is `failed`. A lease that
  expires during the last attempt also ends in `failed`.
- Ordering between messages is not guaranteed.

## Privacy and security

- Rendered subjects and bodies are encrypted at rest (AES-GCM via `ax.secrets`, bound to
  table/row/field), in the outbox and in the local mailbox. Suppressed messages store no content.
- Sensitive templates (e.g. invitations with a one-time link): content is never returned by the API
  (`content_state: redacted`) and is erased as soon as the message is sent.
- Retention (`axentra maintenance purge`): rendered content of finished messages and mailbox
  entries are erased after `notify.content_retention_days` (30); finished messages including the
  recipient address are deleted after `notify.message_retention_days` (180). Queued/sending messages
  are never purged.
- Recipient addresses (and `recipient_user_id`) are personal data. They are stored in plain text
  (needed for delivery and filtering), visible to `notify:manage` (product) and `notify:send`
  (tenant). Deleting a user sets `recipient_user_id` to null; the address stays until retention.
  Audit events contain the template key, category and status, not the address.
- `last_error` is redacted (tokens, keys, URLs with passwords) and truncated.
- Variables are rendered as given: a sender who controls a variable used in an `href` controls the
  link target. Keep links in templates or build them server-side.
- Row-level security on all four tables (`axentra_scope_allows(product_id, tenant_id)`).

## Configuration (`[notify]`)

`provider` (`local`|`smtp`), `sender`, `smtp_host`, `smtp_port`, `smtp_username`,
`smtp_password_ref`, `smtp_starttls`, `smtp_ca_file`, `smtp_timeout_seconds`, `max_attempts`,
`backoff_base_seconds`, `backoff_max_seconds`, `lease_seconds`, `content_retention_days`,
`message_retention_days`. Readiness (`GET /v1/health/ready`) includes `notify_provider` (sender and
provider configuration complete, secrets resolvable; no network calls).

## Limitations / TODO

- Email only; SMS/push adapters, implicit TLS (SMTPS/465), attachments and per-product sender
  addresses do not exist yet.
- No unsubscribe links/List-Unsubscribe header; opt-outs only through the preferences API, and only
  for addresses that belong to users.
- The SMTP provider opens one connection per message.
- The dispatcher is not yet registered as a job of the events module; call `run_once` from a worker
  or run `axentra notify-dispatch --loop`.
- Template history is not kept (messages store the rendered content and template version).
