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

from collections.abc import Callable, Sequence
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from axentra.access.api_keys import ApiKeyService
from axentra.access.authorizer import Authorizer
from axentra.access.definitions import AccessDefinitionService
from axentra.access.product_permission_service import ProductPermissionService
from axentra.access.roles import RoleService
from axentra.audit.log import AuditLog
from axentra.billing.service import BillingService
from axentra.config.secrets import Keyring, SecretBox, keyring_from_settings
from axentra.config.settings import DeploymentMode, Environment, Settings
from axentra.core.errors import ConfigurationError
from axentra.data.database import Database
from axentra.data.migrations import Migration, MigrationRunner, SchemaCheck, discover_migrations
from axentra.data.record_service import RecordService
from axentra.data.reencrypt import EncryptedColumn, ReencryptReport, builtin_encrypted_columns, reencrypt
from axentra.identity.service import IdentityService
from axentra.notify.service import NotifyService
from axentra.observability.metrics import MetricsRegistry, register_db_pool_metrics
from axentra.observability.tracing import setup_tracing
from axentra.search.service import SearchService
from axentra.storage.service import StorageService
from axentra.tenancy.models import Product
from axentra.tenancy.service import TenancyService
from axentra.usage.service import UsageService

if TYPE_CHECKING:
    from axentra.identity.oidc import OidcService

logger = logging.getLogger(__name__)


def _database_url(settings: Settings) -> str:
    if settings.database.url_ref:
        from axentra.config.secrets import resolve_secret

        return resolve_secret(settings.database.url_ref)
    return settings.database.url


def _migration_url(settings: Settings) -> str:
    """``database.migration_url_ref`` > ``database.migration_url`` > the application URL."""
    if settings.database.migration_url_ref:
        from axentra.config.secrets import resolve_secret

        return resolve_secret(settings.database.migration_url_ref)
    return settings.database.migration_url or _database_url(settings)


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
    def __init__(
        self, settings: Settings, *, database: Database | None = None, keyring: Keyring | None = None
    ) -> None:
        """``database``: a prepared :class:`Database` (default: built from ``settings.database``).
        ``keyring``: the master keys, when the embedding application loads them itself (default:
        ``security.master_keys_ref`` / ``master_keys``; then the ref is not required in production)."""
        settings.validate_security(keyring_injected=keyring is not None)
        self.settings = settings
        self.db = database or Database(
            _database_url(settings),
            min_size=settings.database.pool_min,
            max_size=settings.database.pool_max,
            statement_timeout_ms=settings.database.statement_timeout_ms,
        )
        self.keyring = (
            keyring
            if keyring is not None
            else keyring_from_settings(
                _dev_keyring_spec(settings),
                settings.security.master_keys_ref,
                production=settings.is_production,
            )
        )
        self.secrets = SecretBox(self.keyring)
        self.audit = AuditLog(self.db)
        self.authz = Authorizer(self.db)
        self.identity = IdentityService(self.db, settings, self.audit)
        self.tenancy = TenancyService(self.db, settings, self.authz, self.audit)
        self.roles = RoleService(self.db, self.authz, self.audit)
        #: Product-defined permissions: ``ax.permissions.register(product, [ProductPermission(...)])``.
        self.permissions = ProductPermissionService(self.db, self.authz, self.audit)
        #: Versioned permission and role definitions of embedding products (``apply``; no "last start wins").
        self.access_definitions = AccessDefinitionService(self.db, self.audit)
        self.api_keys = ApiKeyService(self.db, self.authz, self.audit)
        self.records = RecordService(self.db, self.authz, self.audit)
        self.oidc: OidcService | None = None
        if settings.oidc:  # needs the "oidc" extra (PyJWT, httpx)
            from axentra.identity.oidc import OidcService

            self.oidc = OidcService(
                self.db,
                settings,
                self.identity,
                self.secrets,
                accept_invitation=self.tenancy.accept_invitation,
            )
        self.storage: StorageService | None = (
            StorageService(self.db, settings, self.authz, self.audit, self.keyring)
            if settings.module_enabled("storage")
            else None
        )
        if self.storage is not None:
            from axentra.storage.policy import check_product_settings

            self.tenancy.product_settings_validators.append(check_product_settings)
        # Observability: metrics registry (ax.metrics.counter(...)) and optional tracing.
        self.metrics = MetricsRegistry()
        register_db_pool_metrics(self.metrics, self.db)
        self.tracing = setup_tracing(settings.observability)
        # Notifications (the API calls ax.on_invitation after creating an invitation).
        self.notify: NotifyService | None = None
        if settings.module_enabled("notify"):
            self.notify = NotifyService(
                self.db, settings, self.authz, self.audit, self.secrets, metrics=self.metrics
            )
            self.on_invitation = self.notify.on_invitation
        # Usage and billing (billing feeds plan limits and billing periods into usage via a policy).
        self.usage = UsageService(self.db, self.authz, self.audit)
        self.billing = BillingService(
            self.db, settings, self.authz, self.audit, events=lambda: getattr(self, "events", None)
        )
        if settings.module_enabled("usage") and settings.module_enabled("billing"):
            self.usage.set_policy(self.billing.usage_policy())
        # Events module (job queue, schedules, events, webhooks). Always constructed (other modules
        # enqueue jobs and publish events through it); module "events" gates its HTTP routes.
        from axentra.events import EventService, JobService, ScheduleService, WebhookService

        self.jobs = JobService(self.db, settings, self.authz, self.audit)
        self.events = EventService(self.db, self.authz, self.audit, self.jobs)
        self.schedules = ScheduleService(self.db, self.authz, self.audit, self.jobs.queue)
        self.webhooks = WebhookService(
            self.db, settings, self.authz, self.audit, self.secrets, self.jobs.queue, self.events
        )
        # Search (tenant-scoped full-text index; ax.search.set_adapter(...) swaps the backend).
        self.search: SearchService | None = (
            SearchService(self.db, settings, self.authz, self.audit)
            if settings.module_enabled("search")
            else None
        )
        self._extra_migrations: list[Migration] = []
        #: Columns re-encrypted by ``axentra secrets reencrypt`` (products add theirs).
        self.encrypted_columns: list[EncryptedColumn] = builtin_encrypted_columns()
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

    def migration_runner(self) -> MigrationRunner:
        """A runner with Axentra's schema, registered product migrations and discovered sources
        (``database.extra_migrations`` and the ``axentra.migrations`` entry point group)."""
        runner = MigrationRunner(_migration_url(self.settings))
        runner.register(self._extra_migrations)
        runner.register(
            discover_migrations(
                self.settings.database.extra_migrations,
                entry_points=self.settings.database.migration_entry_points,
            )
        )
        return runner

    def migrate(
        self,
        *,
        allow_newer: bool = False,
        before_apply: Callable[[list[Migration]], None] | None = None,
    ) -> list[str]:
        """Apply pending migrations (see :meth:`MigrationRunner.migrate` for the arguments)."""
        return self.migration_runner().migrate(allow_newer=allow_newer, before_apply=before_apply)

    def schema_status(self, namespaces: Sequence[str] | None = None) -> SchemaCheck:
        """Compare the database schema with the code (read through the application pool)."""
        runner = self.migration_runner()
        with self.db.pool.connection() as conn:
            try:
                return runner.check(namespaces, conn=conn)
            finally:
                conn.rollback()

    def require_current_schema(self, namespaces: Sequence[str] | None = None) -> SchemaCheck:
        """Serving gate: raise ``SchemaNotCurrent`` on pending or unknown migrations."""
        runner = self.migration_runner()
        with self.db.pool.connection() as conn:
            try:
                return runner.require_current(namespaces, conn=conn)
            finally:
                conn.rollback()

    def schema_ready(self) -> bool:
        """Readiness check: True when the schema is current (False on any error)."""
        try:
            return self.schema_status().current
        except Exception:
            logger.warning("schema check failed", exc_info=True)
            return False

    def register_encrypted_column(self, column: EncryptedColumn) -> None:
        """Product backends declare their SecretBox columns so key rotation covers them."""
        self.encrypted_columns.append(column)

    def reencrypt_secrets(self, *, dry_run: bool = False, batch_size: int = 500) -> ReencryptReport:
        """Re-encrypt stored values under the active key (``axentra secrets reencrypt``)."""
        return reencrypt(
            self.db, self.secrets, self.encrypted_columns, dry_run=dry_run, batch_size=batch_size
        )

    def start(self) -> None:
        if self._started:
            return
        self.db.open()
        relaxed = not self.settings.is_production
        info = self.db.check_role(
            allow_superuser=self.settings.database.allow_superuser or relaxed,
            allow_table_owner=self.settings.database.allow_table_owner or relaxed,
        )
        if info["table_owner"] and self.settings.is_production:
            logger.warning(
                "the database role owns tables protected by row-level security (it could switch RLS off);"
                " use a separate owner role for migrations (database.allow_table_owner = false enforces it)"
            )
        if self.settings.database.require_current_schema:
            try:
                self.require_current_schema()
            except Exception:
                self.db.close()
                raise
        if self.settings.mode is DeploymentMode.SINGLE:
            self.tenancy.ensure_single_product()
        # Mirror product permissions registered in process (later registrations sync at once).
        self.permissions.sync()
        self._started = True

    def single_product(self) -> Product | None:
        return self.tenancy.single_product()

    def close(self) -> None:
        if self.oidc is not None:
            self.oidc.close()
        self.tracing.shutdown()
        self.db.close()
        self._started = False

    def require_started(self) -> None:
        if not self._started:
            raise ConfigurationError("call Axentra.start() first")
