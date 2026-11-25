# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
from collections import ChainMap
from typing import Any, Optional, cast

from ops import Container, ModelError, Unit
from ops.pebble import CheckStatus, Layer, LayerDict, ServiceInfo, ServiceStatus

from cli import CommandLine
from configs import ConfigFile
from constants import (
    CA_BUNDLE_PATH,
    CONFIG_FILE_PATH,
    COURIER_SERVICE,
    KRATOS_ADMIN_PORT,
    KRATOS_PUBLIC_PORT,
    PEBBLE_READY_CHECK_NAME,
    VERIFICATION_EMAIL_TEMPLATE_TARGET_PATH,
    WORKLOAD_CONTAINER,
    WORKLOAD_SERVICE,
)
from env_vars import DEFAULT_CONTAINER_ENV, EnvVarConvertible
from exceptions import PebbleServiceError

logger = logging.getLogger(__name__)

PEBBLE_LAYER_DICT = {
    "summary": "pebble layer",
    "description": "pebble layer for kratos",
    "services": {
        WORKLOAD_SERVICE: {
            "override": "replace",
            "summary": "entrypoint of the kratos image",
            "command": f"kratos serve all --config {CONFIG_FILE_PATH}",
            "startup": "disabled",
        },
        COURIER_SERVICE: {
            "override": "replace",
            "summary": "kratos courier worker",
            "command": f"kratos courier watch --config {CONFIG_FILE_PATH}",
            "startup": "disabled",
        },
    },
    "checks": {
        PEBBLE_READY_CHECK_NAME: {
            "override": "replace",
            "level": "ready",
            "http": {"url": f"http://localhost:{KRATOS_ADMIN_PORT}/admin/health/ready"},
        },
        "alive": {
            "override": "replace",
            "level": "alive",
            "http": {"url": f"http://localhost:{KRATOS_ADMIN_PORT}/admin/health/alive"},
        },
    },
}


class WorkloadService:
    """Workload service abstraction running in a Juju unit."""

    def __init__(self, unit: Unit) -> None:
        self._version = ""

        self._unit: Unit = unit
        self._container: Container = unit.get_container(WORKLOAD_CONTAINER)
        self._cli = CommandLine(self._container)

    @property
    def version(self) -> str:
        self._version = self._cli.get_service_version() or ""
        return self._version

    @version.setter
    def version(self, version: str) -> None:
        if not version:
            return

        try:
            self._unit.set_workload_version(version)
        except Exception as e:
            logger.error("Failed to set workload version: %s", e)
            return

        self._version = version

    def get_service(self, name: str = WORKLOAD_SERVICE) -> Optional[ServiceInfo]:
        """Get service by name."""
        try:
            return self._container.get_service(name)
        except (ModelError, ConnectionError) as e:
            logger.error("Failed to get pebble service: %s", e)
            return None

    def is_running(self, name: str = WORKLOAD_SERVICE) -> bool:
        """Checks whether the service is running."""
        if not (service := self.get_service(name)):
            return False

        if not service.is_running():
            return False

        if name == WORKLOAD_SERVICE:
            c = self._container.get_checks().get(PEBBLE_READY_CHECK_NAME)
            return c.status == CheckStatus.UP

        return True

    def is_failing(self, name: str = WORKLOAD_SERVICE) -> bool:
        """Checks whether the service has crashed."""
        if not (service := self.get_service(name)):
            return False

        # For the kratos service, we take into account the pebble ready check
        if name == WORKLOAD_SERVICE:
            if c := self._container.get_checks().get(PEBBLE_READY_CHECK_NAME):
                return c.failures > 0

        # Check for explicit pebble service error status
        if service.current == ServiceStatus.ERROR:
            return True

        # Service is 'active' or 'inactive'. For 'disabled' services, 'inactive' is a valid state and not a failure
        return False

    def open_ports(self) -> None:
        self._unit.open_port(protocol="tcp", port=KRATOS_PUBLIC_PORT)
        self._unit.open_port(protocol="tcp", port=KRATOS_ADMIN_PORT)

    def push_ca_certs(self, ca_certs: str) -> None:
        self._container.push(str(CA_BUNDLE_PATH), ca_certs, make_dirs=True)

    def push_verification_email_template(self, content: str) -> None:
        """Pushes the verification email template to the workload container."""
        self._container.push(VERIFICATION_EMAIL_TEMPLATE_TARGET_PATH, content, make_dirs=True)


_LAYER_SECTIONS = ("services", "checks", "log-targets")
# Pebble prints a check's default threshold into the plan even when the layer sets none.
_PEBBLE_DEFAULTED_KEYS = frozenset({"threshold"})


def plan_contains_layer(container: Container, layer: Layer | LayerDict) -> bool:
    """Report whether the container's plan already holds everything `layer` would set.

    Pebble announces a plan change for every `add_layer`, even an identical one, and before
    v1.33 each announcement makes it resend every forwarded service's log buffer. Callers skip
    `add_layer` when this returns True. Any difference, or an entry this cannot compare, returns
    False, which only costs the `add_layer` that was always made.
    """
    layer_obj = layer if isinstance(layer, Layer) else Layer(layer)
    layer_dict = cast(dict[str, Any], layer_obj.to_dict())
    plan_dict = cast(dict[str, Any], container.get_plan().to_dict())
    for section in _LAYER_SECTIONS:
        for name, entry in layer_dict.get(section, {}).items():
            planned_entry = plan_dict.get(section, {}).get(name)
            if not isinstance(planned_entry, dict):
                return False
            expected = {key: value for key, value in entry.items() if key != "override"}
            if "environment" in expected:
                # Pebble stores a service's environment as strings, YAML-style for booleans.
                expected["environment"] = {
                    key: str(value).lower() if isinstance(value, bool) else str(value)
                    for key, value in expected["environment"].items()
                }
            actual = {
                key: value
                for key, value in cast(dict[str, Any], planned_entry).items()
                if key != "override" and (key in expected or key not in _PEBBLE_DEFAULTED_KEYS)
            }
            if actual != expected:
                return False
    return True


class PebbleService:
    """Pebble service abstraction running in a Juju unit."""

    def __init__(self, unit: Unit) -> None:
        self._unit = unit
        self._container = unit.get_container(WORKLOAD_CONTAINER)
        self._layer_dict: LayerDict = PEBBLE_LAYER_DICT
        self.config_changed = False

    def plan(self, layer: Layer, config_file: ConfigFile) -> None:
        if not plan_contains_layer(self._container, layer):
            self._container.add_layer(WORKLOAD_SERVICE, layer, combine=True)
        current_config_file = ConfigFile.from_workload_container(self._container)
        self.config_changed = config_file != current_config_file

        try:
            if self.config_changed:
                self._container.push(CONFIG_FILE_PATH, config_file.content, make_dirs=True)
                self._container.restart(WORKLOAD_SERVICE)
            else:
                self._container.replan()
        except Exception as e:
            raise PebbleServiceError(f"Pebble failed to restart the workload service. Error: {e}")

    def restart(self, name: str = WORKLOAD_SERVICE) -> None:
        """Restarts the specified pebble service."""
        try:
            self._container.restart(name)
        except Exception as e:
            raise PebbleServiceError(f"Pebble failed to restart the {name} service. Error: {e}")

    def stop(self, name: str = WORKLOAD_SERVICE) -> None:
        """Stops the specified pebble service."""
        try:
            self._container.stop(name)
        except Exception as e:
            raise PebbleServiceError(f"Pebble failed to stop the {name} service. Error: {e}")

    def render_pebble_layer(self, *env_var_sources: EnvVarConvertible) -> Layer:
        updated_env_vars = ChainMap(*(source.to_env_vars() for source in env_var_sources))  # type: ignore
        env_vars = {
            **DEFAULT_CONTAINER_ENV,
            **updated_env_vars,
        }
        self._layer_dict["services"][WORKLOAD_SERVICE]["environment"] = env_vars
        self._layer_dict["services"][COURIER_SERVICE]["environment"] = env_vars

        return Layer(self._layer_dict)
