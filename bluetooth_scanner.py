import logging
import re
import subprocess

from utils import announce_privileged_action, get_palette

logger = logging.getLogger(__name__)
PROTOCOL_LINE = re.compile(r'^"([^"]+)"')
DEVICE_LINE = re.compile(r"(?:Device\s+|dev_)([0-9A-Fa-f:]{17})\s*(.*)")
RSSI_LINE = re.compile(r"Device\s+([0-9A-Fa-f:]{17})\s+RSSI:\s+(-?\d+)")

class BluetoothScanner:
    """A class to scan for Bluetooth devices and get device information."""

    def scan(self, adapter="hci0", mode="classic", duration=20):
        """Scans for nearby Bluetooth devices using classic, BLE, or both modes."""
        if mode == "classic":
            return self.scan_classic(adapter)
        if mode == "ble":
            return self.scan_ble(adapter, duration)
        if mode == "mixed":
            return self.scan_mixed(adapter, duration)

        print(f"[!] Modo de escaneo no reconocido: {mode}")
        logger.error("Unknown scan mode requested: %s", mode)
        return {}

    def scan_classic(self, adapter="hci0"):
        """Scans for nearby Bluetooth Classic devices."""
        print(f"[*] Escaneando Bluetooth clásico usando {adapter}...")
        announce_privileged_action(
            "el escaneo activo con hcitool requiere acceso privilegiado al adaptador Bluetooth",
            "scanner.scan_classic",
        )
        palette = get_palette()
        try:
            output = subprocess.check_output(["sudo", "hcitool", "-i", adapter, "scan"], text=True)
            lines = output.strip().splitlines()[1:]
            rows = []
            for idx, line in enumerate(lines):
                parts = line.split(maxsplit=1)
                if not parts:
                    continue
                mac = parts[0]
                name = parts[1] if len(parts) > 1 else "Desconocido"
                rows.append({"mac": mac.upper(), "name": name, "kind": "Classic", "rssi": ""})

            devices = self._print_scan_rows(rows, palette)
            logger.info("Classic scan completed on %s. Devices found: %s", adapter, list(devices.values()))
            return devices
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"[!] Error durante el escaneo clásico: {e}")
            logger.error("Classic scan failed on %s: %s", adapter, e)
            return {}

    def scan_ble(self, adapter="hci0", duration=20):
        """Scans for Bluetooth Low Energy advertisements using bluetoothctl."""
        print(f"[*] Escaneando Bluetooth LE usando {adapter} durante {duration} segundos...")
        announce_privileged_action(
            "el escaneo BLE usa bluetoothctl para activar descubrimiento LE",
            "scanner.scan_ble",
        )
        palette = get_palette()
        try:
            subprocess.run(
                ["sudo", "hciconfig", adapter, "up"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                timeout=5,
            )
            output = subprocess.check_output(
                ["bluetoothctl", "--timeout", str(duration), "scan", "on"],
                text=True,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
            )
            rows = self._parse_bluetoothctl_scan(output)
            devices = self._print_scan_rows(rows, palette)
            logger.info("BLE scan completed on %s. Devices found: %s", adapter, list(devices.values()))
            return devices
        except subprocess.TimeoutExpired as e:
            print(f"[!] El escaneo BLE excedió el tiempo configurado: {e}")
            logger.error("BLE scan timed out on %s: %s", adapter, e)
            return {}
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"[!] Error durante el escaneo BLE: {e}")
            logger.error("BLE scan failed on %s: %s", adapter, e)
            return {}

    def scan_mixed(self, adapter="hci0", duration=20):
        """Runs Classic and BLE scans and merges the results."""
        print("[*] Ejecutando escaneo mixto: clásico + BLE.")
        classic = self.scan_classic(adapter)
        ble = self.scan_ble(adapter, duration)
        merged = {}
        for mac in list(classic.values()) + list(ble.values()):
            if mac not in merged.values():
                merged[len(merged)] = mac
        if merged:
            print(f"[+] Total único detectado en modo mixto: {len(merged)} dispositivo(s).")
        return merged

    def _parse_bluetoothctl_scan(self, output):
        devices = {}
        for raw_line in output.splitlines():
            line = raw_line.strip()
            rssi_match = RSSI_LINE.search(line)
            if rssi_match:
                mac = rssi_match.group(1).upper()
                rssi = rssi_match.group(2)
                devices.setdefault(mac, {"mac": mac, "name": "Desconocido", "kind": "BLE", "rssi": ""})
                devices[mac]["rssi"] = rssi
                continue

            device_match = DEVICE_LINE.search(line)
            if device_match:
                mac = device_match.group(1).upper()
                name = device_match.group(2).strip() or "Desconocido"
                if "RSSI:" in name:
                    name = name.split("RSSI:", 1)[0].strip() or "Desconocido"
                devices.setdefault(mac, {"mac": mac, "name": name, "kind": "BLE", "rssi": ""})
                if name != "Desconocido":
                    devices[mac]["name"] = name
                continue

        return list(devices.values())

    @staticmethod
    def _print_scan_rows(rows, palette):
        if not rows:
            print("[-] No se encontraron dispositivos.")
            return {}

        devices = {}
        print(f"{palette['success']}[+] Dispositivos encontrados:{palette['reset']}")
        print("┌────┬─────────────────┬─────────┬──────┬──────────────────────────────┐")
        print("│ #  │ MAC             │ Tipo    │ RSSI │ Alias                        │")
        print("├────┼─────────────────┼─────────┼──────┼──────────────────────────────┤")
        for idx, row in enumerate(rows):
            mac = row["mac"]
            name = row.get("name") or "Desconocido"
            kind = row.get("kind") or "N/D"
            rssi = str(row.get("rssi") or "")
            devices[idx] = mac
            print(f"│ {idx:>2} │ {mac:<15} │ {kind:<7} │ {rssi:<4} │ {name[:28]:<28} │")
        print("└────┴─────────────────┴─────────┴──────┴──────────────────────────────┘")
        return devices

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
