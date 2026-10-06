import logging
import os
import shutil
import subprocess
import sys
from typing import Dict, Set

ALTERNATIVE_COMMANDS = {
    "ussp-push": ["ussp-push", "obexftp"],
}

logger = logging.getLogger(__name__)

_SUDO_MESSAGES_SHOWN: Set[str] = set()


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    stream = sys.stdout
    return getattr(stream, "isatty", lambda: False)()


def get_palette() -> Dict[str, str]:
    if not _supports_color():
        return {"primary": "", "accent": "", "warning": "", "success": "", "reset": ""}
    return {
        "primary": "\033[95m",
        "accent": "\033[94m",
        "warning": "\033[93m",
        "success": "\033[92m",
        "reset": "\033[0m",
    }


def announce_privileged_action(reason: str, context: str) -> None:
    """Informa al usuario que la operación usará sudo y puede requerir contraseña."""
    key = context or reason
    if key in _SUDO_MESSAGES_SHOWN:
        return

    palette = get_palette()
    print(
        f"{palette['warning']}[!] Se requerirán privilegios de superusuario:{palette['reset']} "
        f"{reason}. Ingresa la contraseña del equipo cuando se solicite."
    )
    logger.info("Aviso de privilegios (%s): %s", context, reason)
    _SUDO_MESSAGES_SHOWN.add(key)


def print_banner():
    """Prints the application banner and quick help."""
    palette = get_palette()
    title = f"{palette['primary']}MD-ATACK-BLUETOOTH v9{palette['reset']}"
    author = f"{palette['accent']}Creado por midesmis / Arnulfo{palette['reset']}"

    ascii_logo = [
        r"███╗   ███╗  ██████╗       █████╗   ████████╗   █████╗    ██████╗  ██╗  ██╗     ██████╗   ██╗       ██╗   ██╗  ███████╗  ████████╗   ██████╗    ██████╗   ████████╗  ██╗  ██╗",
        r"████╗ ████║  ██╔══██╗     ██╔══██╗  ╚══██╔══╝  ██╔══██╗  ██╔════╝  ██║ ██╔╝     ██╔══██╗  ██║       ██║   ██║  ██╔════╝  ╚══██╔══╝  ██╔═══██╗  ██╔═══██╗  ╚══██╔══╝  ██║  ██║",
        r"██╔████╔██║  ██║  ██║     ███████║     ██║     ███████║  ██║       █████╔╝      ██████╔╝  ██║       ██║   ██║  █████╗       ██║     ██║   ██║  ██║   ██║     ██║     ███████║",
        r"██║╚██╔╝██║  ██║  ██║     ██╔══██║     ██║     ██╔══██║  ██║       ██╔═██╗      ██╔══██╗  ██║       ██║   ██║  ██╔══╝       ██║     ██║   ██║  ██║   ██║     ██║     ██╔══██║",
        r"██║ ╚═╝ ██║  ██████╔╝     ██║  ██║     ██║     ██║  ██║  ╚██████╗  ██║  ██╗     ██████╔╝  ███████╗  ╚██████╔╝  ███████╗     ██║     ╚██████╔╝  ╚██████╔╝     ██║     ██║  ██║",
        r"╚═╝     ╚═╝  ╚═════╝      ╚═╝  ╚═╝     ╚═╝     ╚═╝  ╚═╝   ╚═════╝  ╚═╝  ╚═╝     ╚═════╝   ╚══════╝   ╚═════╝   ╚══════╝     ╚═╝      ╚═════╝    ╚═════╝      ╚═╝     ╚═╝  ╚═╝",
    ]

    print("=" * 80)
    for line in ascii_logo:
        print(f"{palette['primary']}{line.center(80)}{palette['reset']}")
    print(title.center(80))
    print(author.center(80))
    print("=" * 80)
    print(
        "Herramienta de auditoría Bluetooth diseñada para entornos de pentesting controlado.\n"
        "Utiliza siempre permisos apropiados y equipos bajo tu control."
    )
    print("-" * 80)
    print(f"{palette['accent']}Módulos principales:{palette['reset']}")
    print("  • Escaneo detallado de dispositivos Bluetooth.")
    print("  • Mapeo de servicios y canales RFCOMM.")
    print("  • Pruebas de estrés Bluetooth con límites operativos.")
    print("  • Transferencia OBEX y revisión PBAP bajo scope autorizado.")
    print("  • Vigilancia de objetivos autorizados con controles de alcance.")
    print("-" * 80)
    print(f"{palette['accent']}Ejemplos rápidos:{palette['reset']}")
    print("  Escaneo mixto:                ./run.sh --auto-select scan --mode mixed --duration 30")
    print("  Información de un dispositivo: ./run.sh info --target-mac AA:BB:CC:DD:EE:FF")
    print("  Dry-run DoS:                  ./run.sh --dry-run dos --target-mac AA:BB:CC:DD:EE:FF")
    print("  DoS con scope:                ./run.sh --scope-file scope.json dos --target-mac AA:BB:CC:DD:EE:FF")
    print("  Force takeover con scope:     ./run.sh --scope-file scope.json force_takeover --target-mac AA:BB:CC:DD:EE:FF --channel 3")
    print("  Objetivos autorizados:        ./run.sh --scope-file scope.json blacklist --auto-select")
    print("  Envío de archivos autorizado: ./run.sh --scope-file scope.json send-file --target-mac AA:BB:CC:DD:EE:FF --file ./demo.txt --interactive")
    print("-" * 80)
    print("Sugerencia: usa --help en cada subcomando para ver opciones avanzadas.")
    print("=" * 80)

def check_dependencies(tools):
    """Checks if the required tools are installed."""
    missing = []
    for tool in tools:
        alternatives = ALTERNATIVE_COMMANDS.get(tool, [tool])
        if not any(shutil.which(candidate) for candidate in alternatives):
            missing.append(tool)
    if missing:
        print(f"[!] Error: Debes instalar las herramientas del sistema antes de continuar: {', '.join(missing)}")
        logger.error("Herramientas faltantes: %s", missing)
        sys.exit(1)
    print("[+] Todas las herramientas necesarias están instaladas.")
    logger.info("Todas las herramientas requeridas están disponibles: %s", tools)

def check_bluetooth_service():
    """Checks if the bluetooth service is active and starts it if it is not."""
    announce_privileged_action(
        "verificar y, si es necesario, iniciar el servicio Bluetooth",
        "check_bluetooth_service",
    )
    try:
        output = subprocess.check_output(
            ["sudo", "service", "bluetooth", "status"],
            text=True,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        if "inactive" in output:
            print("[!] El servicio Bluetooth está desactivado. Activándolo...")
            subprocess.run(
                ["sudo", "service", "bluetooth", "start"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
            print("[+] Servicio Bluetooth activado.")
            logger.info("Servicio Bluetooth se inició automáticamente.")
        else:
            print("[+] El servicio Bluetooth ya está activado.")
            logger.info("Servicio Bluetooth ya estaba activo.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[!] Error al verificar o activar el servicio Bluetooth: {e}")
        logger.error("Error comprobando el servicio Bluetooth: %s", e)
        sys.exit(1)

def get_available_adapters():
    """Detects and returns a list of available Bluetooth adapters."""
    try:
        import re
        output = subprocess.check_output(["hciconfig"], text=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        adapters = re.findall(r'^(hci\d+)', output, re.MULTILINE)
        logger.debug("Adaptadores detectados: %s", adapters)
        return adapters
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Error: No se pudo ejecutar 'hciconfig'. Asegúrate de que bluez está instalado.")
        logger.error("No se pudo ejecutar hciconfig para detectar adaptadores.")
        return []
    except Exception as e:
        print(f"[!] Error inesperado al buscar adaptadores: {e}")
        logger.exception("Error inesperado al detectar adaptadores: %s", e)
        return []
