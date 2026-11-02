-- Users without an email address (e.g. created from an external identity whose provider sends
-- no verified email claim, or by an import). The unique index on lower(email) stays: PostgreSQL
-- unique indexes ignore NULLs, so any number of users may have no address, while every address
-- still belongs to at most one user. Such users cannot log in with a password or accept an
-- invitation bound to an email address.
ALTER TABLE axentra_users ALTER COLUMN email DROP NOT NULL;
UPDATE axentra_users SET email = NULL WHERE email = '';
ALTER TABLE axentra_users ADD CONSTRAINT axentra_users_email_not_blank CHECK (email IS NULL OR email <> '');
