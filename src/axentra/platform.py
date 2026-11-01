"""The :class:`Axentra` facade: one object that wires settings, database and all services.

Library use inside a product backend::

    from axentra import load_settings
    from axentra.platform import Axentra

    ax = Axentra.from_settings(load_settings())
    ax.migrate()          # once per deployment (or `axentra migrate`)
    ax.start()
    principal = ax.api_keys.authenticate(token)          # or ax.identity.resolve_session(cookie)
    ax.records.create(principal, product_id, tenant_id, "invoices", {"total": 42})

The HTTP API (``axentra.api``) is a thin layer over exactly these services.
"""

from __future__ import annotations

import logging
from pathlib import Path

from axentra.access.api_keys import ApiKeyService
from axentra.access.authorizer import Authorizer
from axentra.access.roles import RoleService
from axentra.audit.log import AuditLog
from axentra.billing.service import BillingService
from axentra.config.secrets import SecretBox, keyring_from_settings
from axentra.config.settings import DeploymentMode, Environment, Settings
from axentra.core.errors import ConfigurationError
from axentra.data.database import Database
from axentra.data.migrations import Migration, MigrationRunner
from axentra.data.record_service import RecordService
from axentra.identity.service import IdentityService
from axentra.tenancy.models import Product
from axentra.tenancy.service import TenancyService
from axentra.usage.service import UsageService

logger = logging.getLogger(__name__)


def _database_url(settings: Settings) -> str:
    if settings.database.url_ref:
        from axentra.config.secrets import resolve_secret

        return resolve_secret(settings.database.url_ref)
    return settings.database.url


def _dev_keyring_spec(settings: Settings) -> str | None:
    """Development: keep a generated keyring in ./var so encrypted values survive restarts."""
    if (
        settings.environment is not Environment.DEVELOPMENT
        or settings.security.master_keys
        or settings.security.master_keys_ref
    ):
        return settings.security.master_keys
    from axentra.config.secrets import generate_key

    path = Path("var/dev-keyring")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"dev1:{generate_key()}\n", encoding="utf-8")
        path.chmod(0o600)
        logger.warning("generated a development keyring at %s (never use it in production)", path)
    return path.read_text(encoding="utf-8").strip()


class Axentra:
    def __init__(self, settings: Settings, *, database: Database | None = None) -> None:
        settings.validate_security()
        self.settings = settings
        self.db = database or Database(
            _database_url(settings),
            min_size=settings.database.pool_min,
            max_size=settings.database.pool_max,
            statement_timeout_ms=settings.database.statement_timeout_ms,
        )
        self.keyring = keyring_from_settings(
            _dev_keyring_spec(settings), settings.security.master_keys_ref, production=settings.is_production
        )
        self.secrets = SecretBox(self.keyring)
        self.audit = AuditLog(self.db)
        self.authz = Authorizer(self.db)
        self.identity = IdentityService(self.db, settings, self.audit)
        self.tenancy = TenancyService(self.db, settings, self.authz, self.audit)
        self.roles = RoleService(self.db, self.authz, self.audit)
        self.api_keys = ApiKeyService(self.db, self.authz, self.audit)
        self.records = RecordService(self.db, self.authz, self.audit)
        # Usage and billing (billing feeds plan limits and billing periods into usage via a policy).
        self.usage = UsageService(self.db, self.authz, self.audit)
        self.billing = BillingService(
            self.db, settings, self.authz, self.audit, events=lambda: getattr(self, "events", None)
        )
        if settings.module_enabled("usage") and settings.module_enabled("billing"):
            self.usage.set_policy(self.billing.usage_policy())
        self._extra_migrations: list[Migration] = []
        self._started = False
        self._init_modules()

    def _init_modules(self) -> None:
        """Hook for optional modules (storage, events, usage, billing, notify); see subclasses/mixins."""

    @classmethod
    def from_settings(cls, settings: Settings) -> Axentra:
        return cls(settings)

    @property
    def mode(self) -> DeploymentMode:
        return self.settings.mode

    def register_migrations(self, migrations: list[Migration]) -> None:
        """Product backends add their own schema (namespace != 'axentra')."""
        self._extra_migrations.extend(migrations)

    def migrate(self) -> list[str]:
        url = self.settings.database.migration_url or _database_url(self.settings)
        runner = MigrationRunner(url)
        runner.register(self._extra_migrations)
        return runner.migrate()

    def start(self) -> None:
        if self._started:
            return
        self.db.open()
        self.db.check_role(
            allow_superuser=self.settings.database.allow_superuser or not self.settings.is_production
        )
        if self.settings.mode is DeploymentMode.SINGLE:
            self.tenancy.ensure_single_product()
        self._started = True

    def single_product(self) -> Product | None:
        return self.tenancy.single_product()

    def close(self) -> None:
        self.db.close()
        self._started = False

    def require_started(self) -> None:
        if not self._started:
            raise ConfigurationError("call Axentra.start() first")
