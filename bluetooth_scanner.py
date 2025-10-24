import logging
import re
import subprocess

from utils import announce_privileged_action, get_palette

logger = logging.getLogger(__name__)
PROTOCOL_LINE = re.compile(r'^"([^"]+)"')

class BluetoothScanner:
    """A class to scan for Bluetooth devices and get device information."""

    def scan(self, adapter="hci0"):
        """Scans for nearby Bluetooth devices."""
        print(f"[*] Escaneando dispositivos Bluetooth cercanos usando {adapter}...")
        announce_privileged_action(
            "el escaneo activo con hcitool requiere acceso privilegiado al adaptador Bluetooth",
            "scanner.scan",
        )
        palette = get_palette()
        try:
            output = subprocess.check_output(["sudo", "hcitool", "-i", adapter, "scan"], text=True)
            lines = output.strip().splitlines()[1:]
            devices = {}
            rows = []
            for idx, line in enumerate(lines):
                parts = line.split(maxsplit=1)
                mac = parts[0]
                name = parts[1] if len(parts) > 1 else "Desconocido"
                devices[idx] = mac
                rows.append((idx, mac, name))
            if not devices:
                print("[-] No se encontraron dispositivos.")
                return {}

            print(f"{palette['success']}[+] Dispositivos encontrados:{palette['reset']}")
            print("┌────┬─────────────────┬───────────────────────────────────────┐")
            print("│ #  │ MAC             │ Alias                                 │")
            print("├────┼─────────────────┼───────────────────────────────────────┤")
            for idx, mac, name in rows:
                print(f"│ {idx:>2} │ {mac:<15} │ {name:<33} │")
            print("└────┴─────────────────┴───────────────────────────────────────┘")
            logger.info("Scan completed on %s. Devices found: %s", adapter, list(devices.values()))
            return devices
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"[!] Error durante el escaneo: {e}")
            logger.error("Scan failed on %s: %s", adapter, e)
            return {}

    def get_device_info(self, mac_address, show_raw=False):
        """Gets detailed information and RFCOMM services about a specific device."""
        print(f"[*] Obteniendo información del dispositivo {mac_address}...")
        announce_privileged_action(
            "inspeccionar servicios SDP con sdptool necesita permisos administrativos",
            "scanner.device_info",
        )
        try:
            output = subprocess.check_output(["sudo", "sdptool", "browse", mac_address], text=True)
            if show_raw:
                print("--- Información Cruda de SDP --- ")
                print(output)
                print("--- Fin de Información Cruda ---")

            services = []
            current_service = None
            last_protocol = None
            for raw_line in output.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("Service Name:"):
                    current_service = line.split(":", 1)[1].strip()
                elif line.startswith("Protocol Descriptor List:"):
                    last_protocol = None
                elif line.startswith('"'):
                    match = PROTOCOL_LINE.match(line)
                    if match:
                        last_protocol = match.group(1).upper()
                elif line.startswith("Protocol:"):
                    last_protocol = line.split(":", 1)[1].strip().upper()
                elif line.startswith("Channel:") and last_protocol == "RFCOMM":
                    if current_service:
                        try:
                            channel = int(line.split(":", 1)[1].strip())
                            services.append({"service": current_service, "channel": channel})
                            logger.info(
                                "Found RFCOMM service '%s' on channel %s for %s",
                                current_service,
                                channel,
                                mac_address,
                            )
                        except (ValueError, IndexError):
                            logger.debug("Ignoring invalid channel line: %s", line)
                    # Reset for next block
                    current_service = None
                    last_protocol = None

            if services:
                print("\n[+] Servicios RFCOMM detectados:")
                print("------------------------------------------")
                print(f"{'Servicio':<28} | {'Canal'}")
                print("------------------------------------------")
                for service in services:
                    print(f"{service['service']:<28} | {service['channel']}")
                print("------------------------------------------")
                print("Utiliza estos canales para ataques más específicos (ej. con rfcomm)." )
            else:
                print("\n[-] No se encontraron servicios RFCOMM en el dispositivo.")
                logger.info("No RFCOMM services detected for %s", mac_address)

            return output
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"[!] No se pudo obtener la información del dispositivo: {e}")
            logger.error("Failed to get SDP info for %s: %s", mac_address, e)
            return None
