import argparse
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Set

logger = logging.getLogger(__name__)

MAC_REGEX = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")

INTRUSIVE_COMMANDS = {
    "dos",
    "send-file",
    "disconnect",
    "rfcomm_connect",
    "force_takeover",
    "get_contacts",
    "blacklist",
}

MAX_THREADS = 300
MAX_PACKET_SIZE = 1024
MAX_DURATION = 300
MAX_ATTEMPTS = 25
MAX_HOLD_SECONDS = 60

DEFAULT_DOS_THREADS = 10
DEFAULT_DOS_DURATION = 30
DEFAULT_PACKET_SIZE = 120

AGGRESSIVE_DOS_THREADS = 200
AGGRESSIVE_DOS_DURATION = 300
AGGRESSIVE_PACKET_SIZE = 600


class ScopeError(ValueError):
    """Raised when an audit scope cannot authorize an operation."""


@dataclass
class AuditScope:
    authorization_id: str
    authorized_macs: Set[str]
    allowed_commands: Set[str]
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None

    def allows_command(self, command: str) -> bool:
        return not self.allowed_commands or command in self.allowed_commands

    def allows_mac(self, mac: Optional[str]) -> bool:
        if not mac or not self.authorized_macs:
            return True
        return normalize_mac(mac) in self.authorized_macs

    def is_active_now(self) -> bool:
        now = datetime.now()
        if self.starts_at and now < self.starts_at:
            return False
        if self.ends_at and now > self.ends_at:
            return False
        return True


def normalize_mac(value: str) -> str:
    candidate = value.strip().upper()
    if not MAC_REGEX.fullmatch(candidate):
        raise ValueError(
            f"'{value}' no es una dirección MAC válida (formato esperado: AA:BB:CC:DD:EE:FF)."
        )
    return candidate


def mac_address(value: str) -> str:
    try:
        return normalize_mac(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def positive_int(value: str, field: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{field} debe ser un número entero.") from exc

    if number <= 0:
        raise argparse.ArgumentTypeError(f"{field} debe ser mayor que cero.")
    return number


def cap_value(value: int, maximum: int, label: str) -> int:
    if value > maximum:
        logger.warning("%s=%s excede el máximo permitido %s; se limitará.", label, value, maximum)
        print(f"[!] {label} excede el máximo permitido ({maximum}). Usando {maximum}.")
        return maximum
    return value


def parse_datetime(value: Optional[str], field: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ScopeError(f"{field} debe estar en formato ISO 8601, por ejemplo 2026-09-17T09:00:00.") from exc


def load_scope_file(path: Optional[str]) -> Optional[AuditScope]:
    if not path:
        return None

    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ScopeError(f"No se pudo leer el archivo de scope '{path}': {exc}") from exc

    authorization_id = str(data.get("authorization_id") or data.get("client") or "").strip()
    if not authorization_id:
        raise ScopeError("El scope debe incluir 'authorization_id' o 'client'.")

    raw_macs = data.get("authorized_macs") or data.get("targets") or []
    authorized_macs = set()
    for raw_mac in raw_macs:
        if isinstance(raw_mac, dict):
            raw_mac = raw_mac.get("mac") or raw_mac.get("target")
        if raw_mac:
            authorized_macs.add(normalize_mac(str(raw_mac)))

    allowed_commands = {
        str(command).strip()
        for command in data.get("allowed_commands", [])
        if str(command).strip()
    }

    scope = AuditScope(
        authorization_id=authorization_id,
        authorized_macs=authorized_macs,
        allowed_commands=allowed_commands,
        starts_at=parse_datetime(data.get("starts_at"), "starts_at"),
        ends_at=parse_datetime(data.get("ends_at"), "ends_at"),
    )
    logger.info(
        "Audit scope loaded: authorization_id=%s, macs=%s, commands=%s",
        scope.authorization_id,
        sorted(scope.authorized_macs),
        sorted(scope.allowed_commands),
    )
    return scope


def ensure_operation_allowed(
    command: str,
    target_mac: Optional[str],
    scope: Optional[AuditScope],
    confirmed_authorized_scope: bool,
    dry_run: bool,
) -> None:
    if command not in INTRUSIVE_COMMANDS:
        return
    if dry_run:
        logger.info("Dry-run allows planning intrusive command %s without privileged execution.", command)
        return
    if not scope and not confirmed_authorized_scope:
        raise ScopeError(
            "Operación intrusiva bloqueada. Usa --scope-file con objetivos autorizados "
            "o --confirm-authorized-scope para confirmar autorización explícita."
        )
    if not scope:
        logger.warning("Intrusive command %s allowed by explicit confirmation without scope file.", command)
        return
    if not scope.is_active_now():
        raise ScopeError("El scope existe, pero la ventana horaria autorizada no está activa.")
    if not scope.allows_command(command):
        raise ScopeError(f"El scope no permite ejecutar el comando '{command}'.")
    if not scope.allows_mac(target_mac):
        raise ScopeError(f"La MAC {target_mac} no está incluida en el scope autorizado.")


def scope_authorized_macs(scope: Optional[AuditScope]) -> Optional[Set[str]]:
    if not scope or not scope.authorized_macs:
        return None
    return set(scope.authorized_macs)
