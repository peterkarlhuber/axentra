-- In-app inbox notifications (channel 'inbox'): a message is stored for its recipient user and
-- read in the product's own UI. It is never handed to a delivery provider (no e-mail, no webhook):
-- it is enqueued as 'sent' with provider 'inbox', so the dispatcher never claims it. read_at marks
-- it as read. Content is encrypted and purged after notify.content_retention_days like any message.

ALTER TABLE axentra_notify_templates DROP CONSTRAINT IF EXISTS axentra_notify_templates_channel_check;
ALTER TABLE axentra_notify_templates ADD CONSTRAINT axentra_notify_templates_channel_check
    CHECK (channel IN ('email', 'sms', 'push', 'inbox'));
ALTER TABLE axentra_notify_messages DROP CONSTRAINT IF EXISTS axentra_notify_messages_channel_check;
ALTER TABLE axentra_notify_messages ADD CONSTRAINT axentra_notify_messages_channel_check
    CHECK (channel IN ('email', 'sms', 'push', 'inbox'));
ALTER TABLE axentra_notify_messages ADD COLUMN read_at timestamptz;
CREATE INDEX axentra_notify_messages_inbox ON axentra_notify_messages
    (product_id, recipient_user_id, created_at DESC, id DESC) WHERE channel = 'inbox';
