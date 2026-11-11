# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any, KeysView, Type, TypeAlias, Union
from urllib.parse import urlparse

import dacite
from charmlibs.interfaces.security_otlp import SecurityOtlpRequirer
from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferRequires,
)
from charms.data_platform_libs.v0.data_interfaces import DatabaseRequires
from charms.hydra.v0.hydra_endpoints import HydraEndpointsRequirer
from charms.identity_platform_login_ui_operator.v0.login_ui_endpoints import (
    LoginUIEndpointsRequirer,
)
from charms.kratos.v0.kratos_login_webhook import KratosLoginWebhookRequirer
from charms.kratos.v0.kratos_registration_webhook import KratosRegistrationWebhookRequirer
from charms.kratos_external_idp_integrator.v1.kratos_external_provider import ExternalIdpRequirer
from charms.smtp_integrator.v0.smtp import SmtpRequires
from charms.tempo_coordinator_k8s.v0.tracing import TracingEndpointRequirer
from charms.traefik_k8s.v0.traefik_route import TraefikRouteRequirer
from jinja2 import Template
from ops import Container, Model
from ops.pebble import Layer
from typing_extensions import Self
from yarl import URL

from configs import ServiceConfigs
from constants import (
    CA_BUNDLE_PATH,
    INTEGRATION_CA_BUNDLE_PATH,
    INTERNAL_ROUTE_INTEGRATION_NAME,
    KRATOS_ADMIN_PORT,
    KRATOS_PUBLIC_PORT,
    PEER_INTEGRATION_NAME,
    POSTGRESQL_DSN_TEMPLATE,
    PUBLIC_ROUTE_INTEGRATION_NAME,
    SECURITY_OTLP_FILTER_BINARY_PATH,
    SECURITY_OTLP_FILTER_POLICY,
    SECURITY_OTLP_FILTER_SERVICE,
    SECURITY_OTLP_FILTER_SOURCE_PATH,
)
from env_vars import EnvVars

logger = logging.getLogger(__name__)

JsonSerializable: TypeAlias = Union[dict[str, Any], list[Any], int, str, float, bool, Type[None]]


class PeerData:
    def __init__(self, model: Model) -> None:
        self._model = model
        self._app = model.app

    def __getitem__(self, key: str) -> JsonSerializable:
        if not (peers := self._model.get_relation(PEER_INTEGRATION_NAME)):
            return {}

        value = peers.data[self._app].get(key)
        return json.loads(value) if value else {}

    def __setitem__(self, key: str, value: Any) -> None:
        if not (peers := self._model.get_relation(PEER_INTEGRATION_NAME)):
            return

        peers.data[self._app][key] = json.dumps(value)

    def pop(self, key: str) -> JsonSerializable:
        if not (peers := self._model.get_relation(PEER_INTEGRATION_NAME)):
            return {}

        data = peers.data[self._app].pop(key, None)
        return json.loads(data) if data else {}

    def keys(self) -> KeysView[str]:
        if not (peers := self._model.get_relation(PEER_INTEGRATION_NAME)):
            return KeysView({})

        return peers.data[self._app].keys()


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    """The data source from the database integration."""

    endpoint: str = ""
    database: str = ""
    username: str = ""
    password: str = ""
    migration_version: str = ""

    @property
    def dsn(self) -> str:
        return POSTGRESQL_DSN_TEMPLATE.substitute(
            username=self.username,
            password=self.password,
            endpoint=self.endpoint,
            database=self.database,
        )

    def to_env_vars(self) -> EnvVars:
        return {
            "DSN": self.dsn,
        }

    @classmethod
    def load(cls, requirer: DatabaseRequires) -> Self:
        if not (database_integrations := requirer.relations):
            return cls()

        integration_id = database_integrations[0].id
        integration_data: dict[str, str] = requirer.fetch_relation_data()[integration_id]

        return cls(
            endpoint=integration_data.get("endpoints", "").split(",")[0],
            database=requirer.database,
            username=integration_data.get("username", ""),
            password=integration_data.get("password", ""),
            migration_version=f"migration_version_{integration_id}",
        )


@dataclass(frozen=True, slots=True)
class TracingData:
    """The data source from the tracing integration."""

    is_ready: bool = False
    http_endpoint: str = ""

    def to_env_vars(self) -> EnvVars:
        if not self.is_ready:
            return {}

        return {
            "TRACING_PROVIDER": "otel",
            "TRACING_PROVIDERS_OTLP_SERVER_URL": self.http_endpoint,
            "TRACING_PROVIDERS_OTLP_INSECURE": "true",
            "TRACING_PROVIDERS_OTLP_SAMPLING_SAMPLING_RATIO": "1.0",
        }

    def to_service_configs(self) -> ServiceConfigs:
        return {"tracing_enabled": self.is_ready}

    @classmethod
    def load(cls, requirer: TracingEndpointRequirer) -> Self:
        if not (is_ready := requirer.is_ready()):
            return cls()

        http_endpoint = urlparse(requirer.get_endpoint("otlp_http"))

        return cls(
            is_ready=is_ready,
            http_endpoint=http_endpoint.geturl().replace(f"{http_endpoint.scheme}://", "", 1),  # type: ignore
        )


@dataclass(frozen=True, slots=True)
class LoginUIEndpointData:
    """The data source from the login-ui integration."""

    login_url: str = ""
    error_url: str = ""
    settings_url: str = ""
    recovery_url: str = ""
    verification_url: str = ""
    webauthn_settings_url: str = ""
    account_linking_settings_url: str = ""
    registration_url: str = ""
    consent_url: str = ""

    def is_ready(self) -> bool:
        return all(v for _, v in self.to_service_configs().items())

    def to_service_configs(self) -> ServiceConfigs:
        return {
            "default_browser_return_url": self.settings_url,
            "login_ui_url": self.login_url,
            "error_ui_url": self.error_url,
            "settings_ui_url": self.settings_url,
            "recovery_ui_url": self.recovery_url,
            "verification_ui_url": self.verification_url,
            "webauthn_settings_url": self.webauthn_settings_url,
            "account_linking_settings_url": self.account_linking_settings_url,
            "registration_ui_url": self.registration_url,
        }

    @classmethod
    def load(cls, requirer: LoginUIEndpointsRequirer) -> Self:
        try:
            login_ui_endpoints = requirer.get_login_ui_endpoints()
        except Exception as exc:
            logger.error("Failed to fetch the login ui endpoints: %s", exc)
            return cls()

        return (
            dacite.from_dict(data_class=LoginUIEndpointData, data=login_ui_endpoints)
            if login_ui_endpoints
            else cls()
        )


@dataclass(frozen=True, slots=True)
class HydraEndpointData:
    """The data source from the login-ui integration."""

    oauth2_provider_url: str = ""

    def to_env_vars(self) -> EnvVars:
        if not self.oauth2_provider_url:
            return {}

        return {
            "OAUTH2_PROVIDER_URL": self.oauth2_provider_url,
        }

    @classmethod
    def load(cls, requirer: HydraEndpointsRequirer) -> Self:
        try:
            hydra_endpoints = requirer.get_hydra_endpoints()
        except Exception as exc:
            logger.error("Failed to fetch the hydra endpoints: %s", exc)
            return cls()

        return (
            cls(oauth2_provider_url=hydra_endpoints["admin_endpoint"])
            if hydra_endpoints
            else cls()
        )


@dataclass(frozen=True, slots=True)
class SmtpData:
    """The data source from the smtp integration."""

    username: str = "test"
    password: str = "test"
    server: str = "mailslurper"
    port: int = 1025
    transport_security: str = "tls"
    skip_ssl_verify: str = "true"

    def to_env_vars(self) -> EnvVars:
        scheme, option = "", ""

        if self.skip_ssl_verify == "true":
            option = "?skip_ssl_verify=true"

        if self.transport_security == "none":
            scheme = "smtp"
            option = "?disable_starttls=true"

        if self.transport_security == "tls":
            scheme = "smtps"

        if self.transport_security == "starttls":
            scheme = "smtp"

        return {
            "COURIER_SMTP_CONNECTION_URI": f"{scheme}://{self.username}:{self.password}@{self.server}:{self.port}/{option}",
        }

    @classmethod
    def load(cls, requirer: SmtpRequires) -> Self:
        if not (smtp_data := requirer.get_relation_data()):
            return cls()

        return cls(
            username=smtp_data.user or "test",
            password=smtp_data.password or "test",
            server=smtp_data.host,
            port=smtp_data.port,
            transport_security=smtp_data.transport_security,
            skip_ssl_verify="true" if smtp_data.skip_ssl_verify else "false",
        )


@dataclass(frozen=True, slots=True)
class PublicRouteData:
    """The data source from the public-route integration."""

    url: URL = URL()
    config: dict = field(default_factory=dict)

    @classmethod
    def _external_host(cls, requirer: TraefikRouteRequirer) -> str:
        if not (relation := requirer._charm.model.get_relation(PUBLIC_ROUTE_INTEGRATION_NAME)):
            return
        if not relation.app:
            return
        return relation.data[relation.app].get("external_host", "")

    @classmethod
    def _scheme(cls, requirer: TraefikRouteRequirer) -> str:
        if not (relation := requirer._charm.model.get_relation(PUBLIC_ROUTE_INTEGRATION_NAME)):
            return
        if not relation.app:
            return
        return relation.data[relation.app].get("scheme", "")

    @classmethod
    def load(cls, requirer: TraefikRouteRequirer) -> "PublicRouteData":
        model, app = requirer._charm.model.name, requirer._charm.app.name
        external_host = cls._external_host(requirer)
        scheme = cls._scheme(requirer)

        external_endpoint = f"{scheme}://{external_host}"

        # template could have use PathPrefixRegexp but going for a simple one right now
        with open("templates/public-route.j2", "r") as file:
            template = Template(file.read())

        ingress_config = json.loads(
            template.render(
                model=model,
                app=app,
                public_port=KRATOS_PUBLIC_PORT,
                external_host=external_host,
            )
        )

        if not external_host:
            logger.error("External hostname is not set on the ingress provider")
            return cls()

        return cls(
            url=URL(external_endpoint),
            config=ingress_config,
        )

    @property
    def secured(self) -> bool:
        return self.url.scheme == "https"

    def to_service_configs(self) -> ServiceConfigs:
        return (
            {"domain": self.url.host, "origin": f"{self.url.scheme}://{self.url.host}"}
            if self.url
            else {}
        )

    def to_env_vars(self) -> EnvVars:
        return (
            {
                "SERVE_PUBLIC_BASE_URL": str(self.url),
                "SELFSERVICE_ALLOWED_RETURN_URLS": json.dumps(
                    [
                        str(
                            self.url.with_path("")
                            .without_query_params()
                            .with_fragment(None)
                            .with_path("/")
                        )
                    ],
                ),
            }
            if self.url
            else {}
        )


@dataclass(frozen=True, slots=True)
class InternalRouteData:
    """The data source from the internal-ingress integration."""

    public_endpoint: URL
    admin_endpoint: URL
    config: dict = field(default_factory=dict)

    @classmethod
    def _external_host(cls, requirer: TraefikRouteRequirer) -> str:
        if not (relation := requirer._charm.model.get_relation(INTERNAL_ROUTE_INTEGRATION_NAME)):
            return
        if not relation.app:
            return
        return relation.data[relation.app].get("external_host", "")

    @classmethod
    def _scheme(cls, requirer: TraefikRouteRequirer) -> str:
        if not (relation := requirer._charm.model.get_relation(INTERNAL_ROUTE_INTEGRATION_NAME)):
            return
        if not relation.app:
            return
        return relation.data[relation.app].get("scheme", "")

    @classmethod
    def load(cls, requirer: TraefikRouteRequirer) -> "InternalRouteData":
        model, app = requirer._charm.model.name, requirer._charm.app.name
        external_host = cls._external_host(requirer)
        scheme = cls._scheme(requirer) or "http"

        external_endpoint = f"{scheme}://{external_host}"

        with open("templates/internal-route.j2", "r") as file:
            template = Template(file.read())

        ingress_config = json.loads(
            template.render(
                model=model,
                app=app,
                public_port=KRATOS_PUBLIC_PORT,
                admin_port=KRATOS_ADMIN_PORT,
                external_host=external_host,
            )
        )

        public_endpoint = URL(
            external_endpoint
            if external_host
            else f"{scheme}://{app}.{model}.svc.cluster.local:{KRATOS_PUBLIC_PORT}"
        )
        admin_endpoint = URL(
            external_endpoint
            if external_host
            else f"{scheme}://{app}.{model}.svc.cluster.local:{KRATOS_ADMIN_PORT}"
        )

        return cls(
            public_endpoint=public_endpoint,
            admin_endpoint=admin_endpoint,
            config=ingress_config,
        )


@dataclass(frozen=True, slots=True)
class RegistrationWebhookConfig:
    """Configuration for a single Kratos registration webhook."""

    url: str = ""
    body: str = ""
    method: str = "POST"
    mode: str = "after"
    methods: tuple[str, ...] = ()
    weight: int = 0
    response_ignore: bool = False
    response_parse: bool = False
    auth_enabled: bool = False
    auth_type: str = "api_key"
    auth_config_name: str = "Authorization"
    auth_config_value: str = ""
    auth_config_in: str = "header"


@dataclass(frozen=True, slots=True)
class RegistrationWebhookData:
    """The data source from the kratos-registration-webhook integration."""

    configs: list[RegistrationWebhookConfig] = field(default_factory=list)

    def to_service_configs(self) -> ServiceConfigs:
        if not self.configs:
            return {}
        sorted_configs = sorted(self.configs, key=lambda c: c.weight)

        before: dict[str, list] = {"hooks": []}
        after: dict[str, list] = {"hooks": []}

        for c in sorted_configs:
            d = asdict(c)
            target = before if c.mode == "before" else after
            if not c.methods:
                target["hooks"].append(d)
            else:
                for m in c.methods:
                    target.setdefault(m, []).append(d)

        return {"registration_flow": {"before": before, "after": after}}

    @classmethod
    def load(cls, requirer: KratosRegistrationWebhookRequirer) -> Self:
        configs = []
        for relation in requirer.relations:
            webhook_data = requirer.consume_relation_data(relation=relation)
            if not webhook_data:
                continue
            configs.append(
                RegistrationWebhookConfig(
                    url=webhook_data.url,
                    body=webhook_data.body,
                    method=webhook_data.method,
                    mode=webhook_data.mode,
                    methods=tuple(webhook_data.methods),
                    weight=webhook_data.weight,
                    response_ignore=webhook_data.response_ignore,
                    response_parse=webhook_data.response_parse,
                    auth_enabled=webhook_data.auth_enabled,
                    auth_type=webhook_data.auth_type or "",
                    auth_config_name=webhook_data.auth_config_name or "",
                    auth_config_value=webhook_data.auth_config_value or "",
                    auth_config_in=webhook_data.auth_config_in or "",
                )
            )
        return cls(configs=configs)


@dataclass(frozen=True, slots=True)
class LoginWebhookConfig:
    """Configuration for a single Kratos login webhook."""

    url: str = ""
    body: str = ""
    method: str = "POST"
    mode: str = "after"
    methods: tuple[str, ...] = ()
    weight: int = 0
    response_ignore: bool = False
    response_parse: bool = False
    auth_enabled: bool = False
    auth_type: str = "api_key"
    auth_config_name: str = "Authorization"
    auth_config_value: str = ""
    auth_config_in: str = "header"


@dataclass(frozen=True, slots=True)
class LoginWebhookData:
    """The data source from the kratos-login-webhook integration."""

    configs: list[LoginWebhookConfig] = field(default_factory=list)

    def to_service_configs(self) -> ServiceConfigs:
        if not self.configs:
            return {}
        sorted_configs = sorted(self.configs, key=lambda c: c.weight)

        before: dict[str, list] = {"hooks": []}
        after: dict[str, list] = {"hooks": []}

        for c in sorted_configs:
            d = asdict(c)
            target = before if c.mode == "before" else after
            if not c.methods:
                target["hooks"].append(d)
            else:
                for m in c.methods:
                    target.setdefault(m, []).append(d)

        return {"login_flow": {"before": before, "after": after}}

    @classmethod
    def load(cls, requirer: KratosLoginWebhookRequirer) -> Self:
        configs = []
        for relation in requirer.relations:
            webhook_data = requirer.consume_relation_data(relation=relation)
            if not webhook_data:
                continue
            configs.append(
                LoginWebhookConfig(
                    url=webhook_data.url,
                    body=webhook_data.body,
                    method=webhook_data.method,
                    mode=webhook_data.mode,
                    methods=tuple(webhook_data.methods),
                    weight=webhook_data.weight,
                    response_ignore=webhook_data.response_ignore,
                    response_parse=webhook_data.response_parse,
                    auth_enabled=webhook_data.auth_enabled,
                    auth_type=webhook_data.auth_type or "",
                    auth_config_name=webhook_data.auth_config_name or "",
                    auth_config_value=webhook_data.auth_config_value or "",
                    auth_config_in=webhook_data.auth_config_in or "",
                )
            )
        return cls(configs=configs)


@dataclass(frozen=True, slots=True)
class ExternalIdpIntegratorData:
    ext_idp_providers: list = field(default_factory=list)

    def to_service_configs(self) -> ServiceConfigs:
        return {
            "external_oidc_providers": self.ext_idp_providers,
        }

    @classmethod
    def load(cls, requirer: ExternalIdpRequirer) -> Self:
        return cls(ext_idp_providers=requirer.get_providers())


@dataclass(frozen=True, slots=True)
class TLSCertificates:
    ca_bundle: str

    @classmethod
    def load(cls, requirer: CertificateTransferRequires) -> Self:
        """Fetch the CA certificates from all "receive-ca-cert" integrations.

        Compose the trusted CA certificates in /etc/ssl/certs/ca-certificates.crt.
        """
        ca_certs = requirer.get_all_certificates()
        ca_bundle = "\n".join(sorted(ca_certs))

        if ca_bundle:
            current_ca_cert = (
                INTEGRATION_CA_BUNDLE_PATH.read_text()
                if INTEGRATION_CA_BUNDLE_PATH.exists()
                else ""
            )
            if current_ca_cert != ca_bundle:
                INTEGRATION_CA_BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)
                INTEGRATION_CA_BUNDLE_PATH.write_text(ca_bundle)
                subprocess.run(["update-ca-certificates", "--fresh"], check=True)
        else:
            if INTEGRATION_CA_BUNDLE_PATH.exists():
                INTEGRATION_CA_BUNDLE_PATH.unlink(missing_ok=True)
                subprocess.run(["update-ca-certificates", "--fresh"], check=True)

        return cls(ca_bundle=CA_BUNDLE_PATH.read_text())


SECURITY_OTLP_LOG_TARGET_PREFIX = "security-otlp"


def _security_otlp_log_target(relation_id: int, endpoint: str, enable: bool) -> dict:
    name = f"{SECURITY_OTLP_LOG_TARGET_PREFIX}-{relation_id}"
    return {
        name: {
            "override": "replace",
            # Points at the filter service (below), not "all": confirmed against
            # Pebble's own Service.LogsTo (research-and-context/pebble/internals/plan/plan.go)
            # that "all" means every service in the plan, so leaving this as "all" would
            # forward the real workload's raw, unfiltered output alongside the filtered
            # copy -- see STATUS.md Next-steps item 4 for the full finding.
            "services": (
                [SECURITY_OTLP_FILTER_SERVICE] if enable else [f"-{SECURITY_OTLP_FILTER_SERVICE}"]
            ),
            "type": "opentelemetry",
            "location": endpoint,
        }
    }


def _security_otlp_filter_service(real_service_name: str) -> dict:
    """TEST SCAFFOLDING, not production -- see STATUS.md Next-steps item 4.

    Pebble service definition for the filter binary: tails `real_service_name`'s own
    captured log stream via Pebble's client API (poc-log-filtering/main.go), applies
    `SECURITY_OTLP_FILTER_POLICY`, and re-emits only matching lines on its own stdout --
    which Pebble captures the same way it captures any service, so the log-target above
    can forward it with no further plumbing. `real_service_name`'s own command is never
    touched, so the `logging` relation's log-target (LogForwarder, a different vendored
    library -- see the same STATUS.md item for why its own `services: ["all"]` also
    needs attention) keeps seeing the full, unfiltered stream.
    """
    return {
        SECURITY_OTLP_FILTER_SERVICE: {
            "override": "replace",
            "command": (
                f"{SECURITY_OTLP_FILTER_BINARY_PATH} "
                f"-service {real_service_name} -policy {SECURITY_OTLP_FILTER_POLICY}"
            ),
            "startup": "enabled",
        }
    }


def _push_security_otlp_filter_binary(container: Container) -> None:
    """TEST SCAFFOLDING, not production -- see STATUS.md Next-steps item 4.

    Delivers the filter binary checked into this charm's own src/ into the workload
    container, unconditionally on every reconcile -- matching push_ca_certs's own
    established idempotency posture (a plain overwrite, not a skip-if-unchanged check).
    Stands in for the still-undecided production packaging mechanism (a charm resource
    or a charmcraft.yaml build part); this is a stopgap, not a design decision.
    """
    container.push(
        str(SECURITY_OTLP_FILTER_BINARY_PATH),
        SECURITY_OTLP_FILTER_SOURCE_PATH.read_bytes(),
        permissions=0o755,
        make_dirs=True,
    )


def configure_security_otlp_log_forwarding(
    container: Container, requirer: SecurityOtlpRequirer, real_service_name: str
) -> None:
    """Forward the workload's security-relevant logs to every related security-otlp endpoint.

    Logs go through a dedicated filter service rather than forwarding everything.
    Builds one Pebble log-target per related `send-security-otlp` relation -- there can be
    more than one, since the relation is intentionally unbounded (see the spec). Also
    disables any previously configured target whose relation is no longer active, so a
    broken relation stops forwarding rather than continuing to ship logs to a stale
    endpoint.
    """
    active_endpoints = requirer.endpoints

    targets: dict = {}
    for relation_id, endpoint in active_endpoints.items():
        targets.update(_security_otlp_log_target(relation_id, endpoint.endpoint, enable=True))

    existing_targets = container.get_plan().to_dict().get("log-targets", {})
    for name in existing_targets:
        if not name.startswith(f"{SECURITY_OTLP_LOG_TARGET_PREFIX}-"):
            continue
        relation_id = int(name.removeprefix(f"{SECURITY_OTLP_LOG_TARGET_PREFIX}-"))
        if relation_id not in active_endpoints:
            targets.update(_security_otlp_log_target(relation_id, "(removed)", enable=False))

    if not targets:
        return

    _push_security_otlp_filter_binary(container)

    layer = Layer(
        {
            "services": _security_otlp_filter_service(real_service_name),
            "log-targets": targets,
        }
    )
    container.add_layer("security-otlp-log-forwarding", layer, combine=True)
    # add_layer() alone only updates pebble's plan -- it does not start the new
    # "security-otlp-filter" service. replan() is what PebbleService.plan() (services.py)
    # already relies on for the primary service; needed here for the same reason, or the
    # filter service is defined but never actually runs.
    container.replan()
