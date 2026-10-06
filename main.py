import argparse
import logging
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler

from bluetooth_attacker import BluetoothAttacker
from blacklist_manager import BlacklistManager, DEFAULT_BLACKLIST_FILE
from bluetooth_scanner import BluetoothScanner
from safety_controls import (
    ScopeError,
    ensure_operation_allowed,
    load_scope_file,
    mac_address,
    positive_int,
    scope_authorized_macs,
)
from utils import (
    check_bluetooth_service,
    check_dependencies,
    get_available_adapters,
    get_palette,
    print_banner,
)

# Configuración de logging

def configure_logging() -> logging.Logger:
    handler = RotatingFileHandler(
        "audit_log.txt",
        maxBytes=1_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(handler)

    return logging.getLogger(__name__)


logger = configure_logging()


def main():
    """Main function to run the Bluetooth attack tool."""

    print_banner()

    session_stats = {
        "start": time.time(),
        "attacks": 0,
        "command": None,
    }

    parser = argparse.ArgumentParser(description="Herramienta de auditoría de seguridad Bluetooth v9.0")
    parser.add_argument('--adapter', help='Adaptador Bluetooth a utilizar (ej. hci0, hci1)')
    parser.add_argument('--auto-select', action='store_true', help='Selecciona automáticamente el primer adaptador disponible si hay más de uno.')
    parser.add_argument('--dry-run', action='store_true', help='Muestra el plan de ejecución sin tocar Bluetooth ni usar sudo.')
    parser.add_argument('--scope-file', help='Archivo JSON con autorización, ventana de auditoría, MACs y comandos permitidos.')
    parser.add_argument('--confirm-authorized-scope', action='store_true', help='Confirma que la operación intrusiva está autorizada si no se usa --scope-file.')
    parser.add_argument('--aggressive', action='store_true', help='Habilita perfiles agresivos de estrés. Requiere scope o confirmación explícita.')
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')

    # Comando de escaneo
    scan_parser = subparsers.add_parser('scan', help='Escanear dispositivos Bluetooth cercanos')
    scan_parser.add_argument(
        '--mode',
        choices=('classic', 'ble', 'mixed'),
        default='mixed',
        help='Tipo de escaneo: classic usa hcitool, ble usa bluetoothctl, mixed combina ambos.',
    )
    scan_parser.add_argument(
        '--duration',
        type=lambda v: positive_int(v, "La duración"),
        default=20,
        help='Duración en segundos del escaneo BLE en modos ble/mixed.',
    )

    # Comando info
    info_parser = subparsers.add_parser('info', help='Obtener información de un dispositivo')
    info_parser.add_argument('--target-mac', required=True, type=mac_address, help='Dirección MAC del dispositivo objetivo')
    info_parser.add_argument('--raw', action='store_true', help='Muestra la salida cruda de sdptool además del resumen.')

    # Comando DoS
    dos_parser = subparsers.add_parser('dos', help='Realizar un ataque DoS a un dispositivo')
    dos_parser.add_argument('--target-mac', required=True, type=mac_address, help='Dirección MAC del dispositivo objetivo')
    dos_parser.add_argument('--package-size', type=lambda v: positive_int(v, "El tamaño de paquete"), default=120, help='Tamaño del paquete para la prueba de estrés')
    dos_parser.add_argument('--threads', type=lambda v: positive_int(v, "El número de hilos"), default=10, help='Número de hilos para la prueba de estrés')
    dos_parser.add_argument('--duration', type=lambda v: positive_int(v, "La duración"), help='Duración en segundos de la prueba de estrés')
    dos_parser.add_argument('--interactive', action='store_true', help='Configura la prueba de estrés de forma interactiva')

    # Comando enviar archivo
    send_file_parser = subparsers.add_parser('send-file', help='Enviar un archivo a un dispositivo')
    send_file_parser.add_argument('--target-mac', required=True, type=mac_address, help='Dirección MAC del dispositivo objetivo')
    send_file_parser.add_argument('--file', required=True, help='Ruta del archivo a enviar')
    send_file_parser.add_argument('--channel', type=lambda v: positive_int(v, "El canal"), help='Canal OBEX a utilizar (si no se especifica se intentará detectar automáticamente)')
    send_file_parser.add_argument('--interactive', action='store_true', help='Permite seleccionar canal OBEX y opciones adicionales de manera interactiva')

    # Comando desconexión forzada
    disconnect_parser = subparsers.add_parser('disconnect', help='Toma el control de un dispositivo intentando conectarse forzosamente')
    disconnect_parser.add_argument('--target-mac', required=True, type=mac_address, help='Dirección MAC del dispositivo objetivo')
    disconnect_parser.add_argument('--attempts', type=lambda v: positive_int(v, "El número de intentos"), default=10, help='Número de intentos de conexión')
    disconnect_parser.add_argument('--auto-pair', action='store_true', help='Activa el agente de auto-emparejamiento para aceptar conexiones automáticamente')
    disconnect_parser.add_argument('--interactive', action='store_true', help='Solicita parámetros de intensidad y duración de la conexión de forma interactiva')
    disconnect_parser.add_argument('--hold-seconds', type=lambda v: positive_int(v, "El tiempo de retención"), default=10, help='Tiempo en segundos para mantener la conexión antes de liberarla (modo automático)')

    # Conexión RFCOMM
    rfcomm_parser = subparsers.add_parser('rfcomm_connect', help='Establecer una conexión RFCOMM persistente a un canal específico')
    rfcomm_parser.add_argument('--target-mac', required=True, type=mac_address, help='Dirección MAC del dispositivo objetivo')
    rfcomm_parser.add_argument('--channel', required=True, type=lambda v: positive_int(v, "El canal"), help='Canal RFCOMM al que conectarse')

    # Ataque combinado
    takeover_parser = subparsers.add_parser('force_takeover', help='Realiza un DoS y luego intenta una conexión RFCOMM')
    takeover_parser.add_argument('--target-mac', required=True, type=mac_address, help='Dirección MAC del dispositivo objetivo')
    takeover_parser.add_argument('--channel', required=True, type=lambda v: positive_int(v, "El canal"), help='Canal RFCOMM para la conexión')
    takeover_parser.add_argument('--duration', type=lambda v: positive_int(v, "La duración"), default=20, help='Duración del ataque DoS inicial en segundos')
    takeover_parser.add_argument('--threads', type=lambda v: positive_int(v, "El número de hilos"), default=10, help='Número de hilos para el ataque DoS')
    takeover_parser.add_argument('--package-size', type=lambda v: positive_int(v, "El tamaño de paquete"), default=600, help='Tamaño del paquete para el ataque DoS')
    takeover_parser.add_argument('--interactive', action='store_true', help='Configura la combinación DoS + RFCOMM de forma interactiva')

    # Emparejamiento
    pair_parser = subparsers.add_parser('pair_and_trust', help='Guía para emparejar y confiar en un dispositivo usando bluetoothctl')
    pair_parser.add_argument('--target-mac', required=True, type=mac_address, help='Dirección MAC del dispositivo a emparejar')

    # Descarga de contactos
    contacts_parser = subparsers.add_parser('get_contacts', help='Descargar la agenda y el historial de llamadas vía OBEX PBAP')
    contacts_parser.add_argument('--target-mac', required=True, type=mac_address, help='Dirección MAC del dispositivo objetivo')

    # Blacklist module
    blacklist_parser = subparsers.add_parser('blacklist', help='Gestionar objetivos autorizados y ejecutar vigilancia automatizada.')
    blacklist_parser.add_argument('--watch-interval', type=lambda v: positive_int(v, "El intervalo de vigilancia"), default=5, help='Segundos entre escaneos cuando el ataque está en marcha (mínimo 5).')
    blacklist_parser.add_argument('--blacklist-file', default=DEFAULT_BLACKLIST_FILE, help='Archivo JSON donde se almacena la lista negra.')

    args = parser.parse_args()
    session_stats["command"] = args.command

    try:
        scope = load_scope_file(args.scope_file)
    except ScopeError as exc:
        print(f"[!] Scope inválido: {exc}")
        logger.error("Invalid audit scope: %s", exc)
        sys.exit(1)

    required_tools = [
        'hcitool',
        'l2ping',
        'sdptool',
        'ussp-push',
        'hciconfig',
        'rfcomm',
        'bluetoothctl',
        'bt-agent',
        'curl',
    ]
    if args.dry_run:
        print("[DRY-RUN] No se verificarán dependencias privilegiadas ni se tocará el adaptador Bluetooth.")
    else:
        check_dependencies(required_tools)
        check_bluetooth_service()

    # Selección de adaptador
    if not args.command:
        parser.print_help()
        return

    if args.dry_run:
        selected_adapter = args.adapter or "hci0"
        print(f"[DRY-RUN] Adaptador planeado: {selected_adapter}")
    else:
        adapters = get_available_adapters()
        if not adapters:
            print("[!] No se encontraron adaptadores Bluetooth. Asegúrate de que esté conectado y los drivers instalados.")
            logger.error("No se detectaron adaptadores Bluetooth.")
            sys.exit(1)

        selected_adapter = args.adapter

        if selected_adapter and selected_adapter not in adapters:
            print(f"[!] El adaptador '{selected_adapter}' no está disponible. Detectados: {', '.join(adapters)}.")
            logger.error("El adaptador %s no está entre los detectados: %s", selected_adapter, adapters)
            sys.exit(1)

        if not selected_adapter:
            if len(adapters) == 1:
                selected_adapter = adapters[0]
                print(f"[*] Usando el único adaptador disponible: {selected_adapter}")
                logger.info("Usando el único adaptador disponible: %s", selected_adapter)
            elif args.auto_select:
                selected_adapter = adapters[0]
                print(f"[*] Selección automática activada. Usando {selected_adapter}")
                logger.info("Selección automática: usando %s (disponibles: %s)", selected_adapter, adapters)
            else:
                print("[!] Hay múltiples adaptadores disponibles. Especifica uno con --adapter o usa --auto-select para escoger el primero automáticamente.")
                print(f"    Detectados: {', '.join(adapters)}")
                logger.error("Múltiples adaptadores detectados sin selección explícita: %s", adapters)
                sys.exit(1)

    logging.info("Comando ejecutado: %s", args.command)
    target_mac = getattr(args, "target_mac", None)
    try:
        ensure_operation_allowed(
            args.command,
            target_mac,
            scope,
            args.confirm_authorized_scope,
            args.dry_run,
        )
    except ScopeError as exc:
        print(f"[!] Operación bloqueada: {exc}")
        logger.error("Operation blocked by safety controls: %s", exc)
        sys.exit(1)

    scanner = BluetoothScanner()

    if args.command == 'scan':
        logger.info("Ejecutando escaneo con el adaptador %s (mode=%s, duration=%s)", selected_adapter, args.mode, args.duration)
        if args.dry_run:
            print(f"[DRY-RUN] Ejecutaría escaneo {args.mode} con {selected_adapter} durante {args.duration}s.")
        else:
            scanner.scan(selected_adapter, mode=args.mode, duration=args.duration)
    elif args.command == 'info':
        logger.info("Obteniendo información de %s", args.target_mac)
        if args.dry_run:
            print(f"[DRY-RUN] Consultaría servicios SDP de {args.target_mac}.")
        else:
            scanner.get_device_info(args.target_mac, show_raw=args.raw)
    elif args.command in {'dos', 'send-file', 'disconnect', 'rfcomm_connect', 'force_takeover', 'pair_and_trust', 'get_contacts'}:
        attacker = BluetoothAttacker(args.target_mac, selected_adapter, dry_run=args.dry_run)
        if args.command == 'dos':
            duration = args.duration if args.duration else None
            mode = "interactive" if args.interactive else ("aggressive" if args.aggressive else "auto")
            logger.info(
                "Ejecutando DoS contra %s (modo=%s, hilos=%s, tamaño=%s, duración=%s)",
                args.target_mac,
                mode,
                args.threads,
                args.package_size,
                duration,
            )
            attacker.dos_attack(
                args.threads,
                args.package_size,
                duration,
                mode=mode,
            )
            if not args.dry_run:
                session_stats["attacks"] += 1
        elif args.command == 'send-file':
            mode = "interactive" if args.interactive else "auto"
            logger.info(
                "Enviando archivo a %s (modo=%s, archivo=%s, canal=%s)",
                args.target_mac,
                mode,
                args.file,
                args.channel,
            )
            attacker.send_file(args.file, channel=args.channel, mode=mode)
        elif args.command == 'disconnect':
            mode = "interactive" if args.interactive else ("aggressive" if args.aggressive else "auto")
            logger.info(
                "Ataque de desconexión contra %s (modo=%s, intentos=%s, auto_pair=%s, hold=%s)",
                args.target_mac,
                mode,
                args.attempts,
                args.auto_pair,
                args.hold_seconds,
            )
            attacker.disconnect(
                attempts=args.attempts,
                auto_pair=args.auto_pair,
                hold_seconds=args.hold_seconds,
                mode=mode,
            )
            if not args.dry_run:
                session_stats["attacks"] += 1
        elif args.command == 'rfcomm_connect':
            logger.info("Conexión RFCOMM a %s (canal=%s)", args.target_mac, args.channel)
            attacker.rfcomm_connect(args.channel)
        elif args.command == 'force_takeover':
            mode = "interactive" if args.interactive else ("aggressive" if args.aggressive else "auto")
            logger.info(
                "Force takeover contra %s (modo=%s, canal=%s, duración=%s, hilos=%s, tamaño_paquete=%s)",
                args.target_mac,
                mode,
                args.channel,
                args.duration,
                args.threads,
                args.package_size,
            )
            attacker.force_takeover(
                args.channel,
                args.duration,
                args.threads,
                args.package_size,
                mode=mode,
            )
            if not args.dry_run:
                session_stats["attacks"] += 1
        elif args.command == 'pair_and_trust':
            logger.info("Mostrando guía de emparejamiento para %s", args.target_mac)
            attacker.pair_and_trust()
        elif args.command == 'get_contacts':
            logger.info("Descargando contactos de %s", args.target_mac)
            attacker.get_contacts()
    elif args.command == 'blacklist':
        logger.info(
            "Iniciando módulo blacklist (archivo=%s, intervalo=%s)",
            args.blacklist_file,
            args.watch_interval,
        )
        manager = BlacklistManager(
            adapter=selected_adapter,
            blacklist_path=args.blacklist_file,
            watch_interval=args.watch_interval,
            dry_run=args.dry_run,
            aggressive=args.aggressive,
            authorized_macs=scope_authorized_macs(scope),
        )
        manager.run()
    else:
        parser.print_help()

    duration = time.time() - session_stats["start"]
    logging.info(
        "Session summary | command=%s | adapter=%s | duration=%.2fs | attacks=%s",
        session_stats.get("command"),
        selected_adapter,
        duration,
        session_stats.get("attacks"),
    )
    logging.info("Auditoría finalizada a las %s", datetime.now())
    palette = get_palette()
    print("\n" + "=" * 80)
    print(
        f"{palette['accent']}[=] Resumen de sesión{palette['reset']} | "
        f"Comando: {session_stats.get('command') or 'N/D'} | "
        f"Adaptador: {selected_adapter} | "
        f"Duración: {duration:.1f} s | "
        f"Ataques ejecutados: {session_stats.get('attacks')}{palette['reset']}"
    )
    print(f"Registro detallado disponible en: audit_log.txt")
    print("=" * 80)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Programa interrumpido por el usuario.")
        sys.exit(0)
    except Exception as exc:
        print(f"[!] Error inesperado: {exc}")
        logger.exception("Error inesperado en la ejecución principal: %s", exc)
        sys.exit(1)
