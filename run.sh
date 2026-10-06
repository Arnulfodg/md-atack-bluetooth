#!/bin/bash

set -euo pipefail

# --- Global configuration ---
REQUIRED_COMMANDS=(hcitool l2ping sdptool ussp-push hciconfig rfcomm bluetoothctl bt-agent curl)
REQUIRED_BUILD_COMMANDS=(gcc make pkg-config)
declare -A COMMAND_ALTERNATIVES=(
    ["ussp-push"]="ussp-push obexftp"
)
PYTHON_MODULES=(PyOBEX bluetooth)
MISSING_PY_MODULES=()
OS_NAME="Linux (desconocido)"
OS_ID="unknown"
PKG_MANAGER="unknown"

MISSING_KEYS=()
MISSING_INFO=()
PACKAGES=()
UNMAPPED=()

ALLOW_SYSTEM_INSTALL="${ALLOW_SYSTEM_INSTALL:-0}"
SKIP_SYSTEM_INSTALL="${SKIP_SYSTEM_INSTALL:-0}"
OFFLINE_MODE="${OFFLINE_MODE:-0}"
OFFLINE_WHEEL_DIR="${OFFLINE_WHEEL_DIR:-offline-packages}"

# --- Helper functions ---

function add_missing() {
    local key="$1"
    local description="$2"
    for existing in "${MISSING_KEYS[@]:-}"; do
        if [[ "$existing" == "$key" ]]; then
            return
        fi
    done
    MISSING_KEYS+=("$key")
    MISSING_INFO+=("$description")
}

function add_package() {
    local package="$1"
    [[ -z "$package" ]] && return
    for existing in "${PACKAGES[@]:-}"; do
        if [[ "$existing" == "$package" ]]; then
            return
        fi
    done
    PACKAGES+=("$package")
}

function add_unmapped() {
    local key="$1"
    for existing in "${UNMAPPED[@]:-}"; do
        if [[ "$existing" == "$key" ]]; then
            return
        fi
    done
    UNMAPPED+=("$key")
}

function description_for_key() {
    local key="$1"
    for idx in "${!MISSING_KEYS[@]}"; do
        if [[ "${MISSING_KEYS[$idx]}" == "$key" ]]; then
            echo "${MISSING_INFO[$idx]}"
            return
        fi
    done
    echo "$key"
}

function map_package() {
    local manager="$1"
    local requirement="$2"
    case "$manager" in
        apt)
            case "$requirement" in
                python3) echo "python3" ;;
                python3-venv) echo "python3-venv" ;;
                python3-dev) echo "python3-dev" ;;
                libbluetooth-dev) echo "libbluetooth-dev" ;;
                gcc|make) echo "build-essential" ;;
                pkg-config) echo "pkg-config" ;;
                hcitool|l2ping|sdptool|hciconfig|rfcomm|bluetoothctl) echo "bluez" ;;
                ussp-push) echo "obexftp" ;;
                bt-agent) echo "bluez-tools" ;;
                curl) echo "curl" ;;
            esac
            ;;
        dnf|yum)
            case "$requirement" in
                python3) echo "python3" ;;
                python3-venv) echo "python3-virtualenv" ;;
                python3-dev) echo "python3-devel" ;;
                libbluetooth-dev) echo "bluez-libs-devel" ;;
                gcc) echo "gcc" ;;
                make) echo "make" ;;
                pkg-config) echo "pkgconf-pkg-config" ;;
                hcitool|l2ping|sdptool|hciconfig|rfcomm|bluetoothctl) echo "bluez" ;;
                ussp-push) echo "obexftp" ;;
                bt-agent) echo "bluez-tools" ;;
                curl) echo "curl" ;;
            esac
            ;;
        pacman)
            case "$requirement" in
                python3|python3-venv|python3-dev) echo "python" ;;
                libbluetooth-dev) echo "bluez" ;;
                gcc|make) echo "base-devel" ;;
                pkg-config) echo "pkgconf" ;;
                hcitool|l2ping|sdptool|hciconfig|rfcomm|bluetoothctl) echo "bluez" ;;
                ussp-push) echo "obexftp" ;;
                bt-agent) echo "bluez-utils" ;;
                curl) echo "curl" ;;
            esac
            ;;
        zypper)
            case "$requirement" in
                python3|python3-venv|python3-dev) echo "python3-devel" ;;
                libbluetooth-dev) echo "bluez-devel" ;;
                gcc) echo "gcc" ;;
                make) echo "make" ;;
                pkg-config) echo "pkg-config" ;;
                hcitool|l2ping|sdptool|hciconfig|rfcomm|bluetoothctl) echo "bluez" ;;
                ussp-push) echo "obexftp" ;;
                bt-agent) echo "bluez" ;;
                curl) echo "curl" ;;
            esac
            ;;
    esac
}

function add_pkg_for_requirement() {
    local requirement="$1"
    local package
    package=$(map_package "$PKG_MANAGER" "$requirement" || true)
    if [[ -n "${package:-}" ]]; then
        add_package "$package"
    else
        add_unmapped "$requirement"
    fi
}

function detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        OS_NAME="${PRETTY_NAME:-${NAME:-$OS_NAME}}"
        OS_ID="${ID:-$OS_ID}"
    else
        OS_NAME="$(uname -s)"
        OS_ID="unknown"
    fi
}

function detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
    elif command -v pacman >/dev/null 2>&1; then
        PKG_MANAGER="pacman"
    elif command -v zypper >/dev/null 2>&1; then
        PKG_MANAGER="zypper"
    else
        PKG_MANAGER="unknown"
    fi
}

function package_manager_label() {
    case "$PKG_MANAGER" in
        apt) echo "apt-get" ;;
        dnf) echo "dnf" ;;
        yum) echo "yum" ;;
        pacman) echo "pacman" ;;
        zypper) echo "zypper" ;;
        *) echo "no detectado" ;;
    esac
}

function check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        add_missing "python3" "Python 3"
        add_pkg_for_requirement "python3"
    else
        if ! python3 -m venv --help >/dev/null 2>&1; then
            add_missing "python3-venv" "Módulo venv de Python (python3-venv)"
            add_pkg_for_requirement "python3-venv"
        elif ! python3 -m ensurepip --help >/dev/null 2>&1; then
            add_missing "python3-venv" "Módulo venv de Python (python3-venv)"
            add_pkg_for_requirement "python3-venv"
        fi
    fi
}

function check_build_tools() {
    for tool in "${REQUIRED_BUILD_COMMANDS[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            case "$tool" in
                gcc) add_missing "$tool" "Compilador C 'gcc'" ;;
                make) add_missing "$tool" "Herramienta de construcción 'make'" ;;
                pkg-config) add_missing "$tool" "Utilidad 'pkg-config'" ;;
                *) add_missing "$tool" "Herramienta de construcción '$tool'" ;;
            esac
            add_pkg_for_requirement "$tool"
        fi
    done
}

function check_system_commands() {
    for cmd in "${REQUIRED_COMMANDS[@]}"; do
        local satisfied=0
        local alternatives="${COMMAND_ALTERNATIVES[$cmd]:-}"
        if [[ -n "$alternatives" ]]; then
            for alt_cmd in $alternatives; do
                if command -v "$alt_cmd" >/dev/null 2>&1; then
                    satisfied=1
                    break
                fi
            done
        else
            if command -v "$cmd" >/dev/null 2>&1; then
                satisfied=1
            fi
        fi
        if [[ $satisfied -eq 1 ]]; then
            continue
        fi
        case "$cmd" in
            ussp-push) add_missing "$cmd" "Comando 'ussp-push' (transferencia OBEX)" ;;
            bt-agent) add_missing "$cmd" "Comando 'bt-agent' (opcional para --auto-pair)" ;;
            *) add_missing "$cmd" "Comando '$cmd'" ;;
        esac
        add_pkg_for_requirement "$cmd"
    done
}

function ensure_pip() {
    local python_bin="$1"

    if "$python_bin" -m pip --version >/dev/null 2>&1; then
        return 0
    fi

    if "$python_bin" -m ensurepip --upgrade >/dev/null 2>&1; then
        "$python_bin" -m pip --version >/dev/null 2>&1 && return 0
    fi

    if [[ "$OFFLINE_MODE" == "1" ]]; then
        return 1
    fi

    if command -v curl >/dev/null 2>&1; then
        local tmpfile
        tmpfile=$(mktemp)
        if curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "$tmpfile"; then
            if "$python_bin" "$tmpfile"; then
                rm -f "$tmpfile"
                return 0
            fi
        fi
        rm -f "$tmpfile"
    fi

    return 1
}

function pip_install_requirements() {
    local python_bin="$1"

    if [[ "$OFFLINE_MODE" == "1" ]]; then
        if [[ -d "$OFFLINE_WHEEL_DIR" ]]; then
            echo "[*] Instalando dependencias desde el directorio local '$OFFLINE_WHEEL_DIR'..."
            # Attempt to install both, maybe they are in the offline dir
            if "$python_bin" -m pip install --no-index --find-links="$OFFLINE_WHEEL_DIR" --upgrade PyBluez-updated && \
               "$python_bin" -m pip install --no-index --find-links="$OFFLINE_WHEEL_DIR" --upgrade --no-deps -r requirements.txt; then
                return 0
            fi
            echo "[!] Falló la instalación desde el repositorio local de paquetes."
        else
            echo "[!] Modo offline habilitado pero no se encontró el directorio '$OFFLINE_WHEEL_DIR'."
        fi
        return 1
    fi

    echo "[*] Instalando PyBluez-updated por separado para evitar conflictos..."
    if ! "$python_bin" -m pip install --upgrade PyBluez-updated; then
        echo "[!] Error al instalar PyBluez-updated."
        return 1
    fi

    echo "[*] Instalando el resto de dependencias desde requirements.txt..."
    if [[ -d "$OFFLINE_WHEEL_DIR" ]]; then
        echo "[*] Usando repositorio local '$OFFLINE_WHEEL_DIR' como caché para pip."
        if "$python_bin" -m pip install --find-links="$OFFLINE_WHEEL_DIR" --upgrade --no-deps -r requirements.txt; then
            return 0
        fi
        echo "[!] Advertencia: la instalación usando el repositorio local falló, intentando instalación estándar."
    fi

    # Install other requirements without their dependencies
    "$python_bin" -m pip install --upgrade --no-deps -r requirements.txt
}

function python_has_modules() {
    MISSING_PY_MODULES=()
    local python_bin="$1"
    for module in "${PYTHON_MODULES[@]}"; do
        if ! "$python_bin" -c "import ${module}" >/dev/null 2>&1; then
            MISSING_PY_MODULES+=("$module")
        fi
    done
    if [[ ${#MISSING_PY_MODULES[@]} -gt 0 ]]; then
        return 1
    fi
    return 0
}

function check_headers() {
    local header_found=0
    local candidates=(
        /usr/include/bluetooth/bluetooth.h
        /usr/include/x86_64-linux-gnu/bluetooth/bluetooth.h
        /usr/include/aarch64-linux-gnu/bluetooth/bluetooth.h
        /usr/include/arm-linux-gnueabihf/bluetooth/bluetooth.h
        /usr/include/arm-linux-gnueabi/bluetooth/bluetooth.h
    )
    for candidate in "${candidates[@]}"; do
        if [[ -f "$candidate" ]]; then
            header_found=1
            break
        fi
    done
    if [[ $header_found -eq 0 ]]; then
        add_missing "libbluetooth-dev" "Cabeceras de desarrollo Bluetooth (libbluetooth-dev)"
        add_pkg_for_requirement "libbluetooth-dev"
    fi
}

function check_python_headers() {
    if ! python3 - <<'PY' >/dev/null 2>&1
import sysconfig
from pathlib import Path

include = sysconfig.get_path("include")
if not include or not (Path(include) / "Python.h").exists():
    raise SystemExit(1)
PY
    then
        add_missing "python3-dev" "Cabeceras de desarrollo de Python (python3-dev / Python.h)"
        add_pkg_for_requirement "python3-dev"
    fi
}

function reset_state() {
    MISSING_KEYS=()
    MISSING_INFO=()
    PACKAGES=()
    UNMAPPED=()
}

function check_requirements() {
    reset_state
    check_python
    check_build_tools
    check_system_commands
    check_headers
    check_python_headers
}

function print_missing() {
    echo "[!] Se detectaron dependencias faltantes en el sistema:"
    for desc in "${MISSING_INFO[@]}"; do
        echo "    - $desc"
    done
    if [[ ${#UNMAPPED[@]} -gt 0 ]]; then
        echo "[!] No se pudo determinar automáticamente el paquete para:"
        for key in "${UNMAPPED[@]}"; do
            echo "    - $(description_for_key "$key")"
        done
    fi
}

function install_packages() {
    local manager="$1"
    shift
    local packages=("$@")

    if [[ ${#packages[@]} -eq 0 ]]; then
        return 0
    fi

    case "$manager" in
        apt)
            echo "[*] Actualizando índices de apt..."
            echo "[!] Se solicitará la contraseña para permitir que apt-get actualice los índices del sistema."
            if ! sudo apt-get update; then
                echo "[!] No se pudo ejecutar 'apt-get update'."
                return 1
            fi
            echo "[*] Instalando paquetes con apt-get: ${packages[*]}"
            echo "[!] Se solicitará la contraseña para instalar dependencias del sistema con apt-get."
            if ! sudo apt-get install -y "${packages[@]}"; then
                echo "[!] Falló la instalación con apt-get."
                return 1
            fi
            ;;
        dnf)
            echo "[*] Instalando paquetes con dnf: ${packages[*]}"
            echo "[!] Se solicitará la contraseña para instalar dependencias del sistema con dnf."
            if ! sudo dnf install -y "${packages[@]}"; then
                echo "[!] Falló la instalación con dnf."
                return 1
            fi
            ;;
        yum)
            echo "[*] Instalando paquetes con yum: ${packages[*]}"
            echo "[!] Se solicitará la contraseña para instalar dependencias del sistema con yum."
            if ! sudo yum install -y "${packages[@]}"; then
                echo "[!] Falló la instalación con yum."
                return 1
            fi
            ;;
        pacman)
            echo "[*] Instalando paquetes con pacman: ${packages[*]}"
            echo "[!] Se solicitará la contraseña para instalar dependencias del sistema con pacman."
            if ! sudo pacman -S --needed --noconfirm "${packages[@]}"; then
                echo "[!] Falló la instalación con pacman."
                return 1
            fi
            ;;
        zypper)
            echo "[*] Instalando paquetes con zypper: ${packages[*]}"
            echo "[!] Se solicitará la contraseña para instalar dependencias del sistema con zypper."
            if ! sudo zypper install -y "${packages[@]}"; then
                echo "[!] Falló la instalación con zypper."
                return 1
            fi
            ;;
        *)
            echo "[!] Instalación automática no soportada para el gestor '$manager'."
            return 1
            ;;
    esac
}

function resolve_system_dependencies() {
    check_requirements
    if [[ ${#MISSING_KEYS[@]} -eq 0 ]]; then
        echo "[+] Dependencias del sistema verificadas correctamente."
        return
    fi

    print_missing

    if [[ "$SKIP_SYSTEM_INSTALL" == "1" ]]; then
        echo "[!] Se solicitó omitir instalaciones automáticas (SKIP_SYSTEM_INSTALL=1). Instala manualmente las dependencias y vuelve a ejecutar."
        exit 1
    fi

    if [[ "$OFFLINE_MODE" == "1" ]]; then
        echo "[!] Modo offline activo. Instala manualmente las dependencias del sistema antes de continuar."
        exit 1
    fi

    if [[ "$PKG_MANAGER" == "unknown" || ${#PACKAGES[@]} -eq 0 ]]; then
        echo "[!] No se pudo determinar los paquetes a instalar automáticamente. Resuelve las dependencias manualmente."
        exit 1
    fi

    echo "[*] Paquetes sugeridos para instalar: ${PACKAGES[*]}"
    local user_choice=""
    if [[ "$ALLOW_SYSTEM_INSTALL" == "1" ]]; then
        user_choice="s"
    else
        read -r -p "¿Deseas que la herramienta intente instalarlos automáticamente? [s/N]: " user_choice
        user_choice=$(printf '%s' "$user_choice" | tr '[:upper:]' '[:lower:]')
    fi

    if [[ "$user_choice" != "s" && "$user_choice" != "si" && "$user_choice" != "y" && "$user_choice" != "yes" ]]; then
        echo "[!] Instalación automática cancelada. Instala manualmente las dependencias faltantes."
        exit 1
    fi

    if ! install_packages "$PKG_MANAGER" "${PACKAGES[@]}"; then
        echo "[!] No se pudieron instalar automáticamente las dependencias del sistema. Verifica tu conexión o permisos."
        exit 1
    fi

    echo "[*] Re-verificando dependencias del sistema..."
    check_requirements
    if [[ ${#MISSING_KEYS[@]} -gt 0 ]]; then
        print_missing
        echo "[!] Aún faltan dependencias después del intento de instalación. Resuélvelas manualmente."
        exit 1
    fi

    echo "[+] Dependencias del sistema verificadas correctamente."
}

function setup_virtualenv() {
    if [[ -d ".venv" ]]; then
        echo 0
        return
    fi

    if python3 -m venv .venv >/dev/null 2>&1; then
        echo 1
        return
    fi

    if python3 -m venv --without-pip .venv >/dev/null 2>&1; then
        echo 1
        return
    fi

    echo "[!] No se pudo crear el entorno virtual. Asegúrate de tener instalado el paquete python3-venv."
    exit 1
}

function install_python_dependencies() {
    local venv_created="$1"
    local python_bin=".venv/bin/python"
    local need_install="$venv_created"

    if [[ ! -x "$python_bin" ]]; then
        echo "[!] El entorno virtual no es válido (no se encontró el ejecutable de Python)."
        exit 1
    fi

    if [[ "$need_install" -eq 0 ]]; then
        if [[ ! -f ".setup_complete" || requirements.txt -nt .setup_complete ]]; then
            need_install=1
        fi
    fi

    if [[ "$need_install" -eq 0 ]]; then
        return
    fi

    if ! ensure_pip "$python_bin"; then
        echo "[!] No se pudo inicializar pip en el entorno virtual."
        if [[ "$OFFLINE_MODE" == "1" ]]; then
            echo "    Ejecuta manualmente: $python_bin -m ensurepip --upgrade"
        fi
        exit 1
    fi

    if [[ "$OFFLINE_MODE" == "1" ]]; then
        if python_has_modules "$python_bin"; then
            echo "[*] Modo offline: dependencias de Python ya presentes."
            touch .setup_complete
            return
        fi
        if pip_install_requirements "$python_bin"; then
            touch .setup_complete
            return
        fi
        local joined
        joined=$(printf '%s ' "${MISSING_PY_MODULES[@]}")
        echo "[!] Modo offline: faltan módulos de Python (${joined% }) y no fue posible instalarlos desde '$OFFLINE_WHEEL_DIR'."
        echo "    Copia las ruedas necesarias a ese directorio o instala manualmente y vuelve a ejecutar."
        exit 1
    fi

    echo "[*] Actualizando pip..."
    if ! "$python_bin" -m pip install --upgrade pip; then
        echo "[!] Advertencia: no se pudo actualizar pip. Continuando con la versión disponible."
    fi

    echo "[*] Instalando dependencias de Python..."
    if ! pip_install_requirements "$python_bin"; then
        echo "[!] Error al instalar dependencias desde requirements.txt."
        if python_has_modules "$python_bin"; then
            echo "[*] Los módulos requeridos ya estaban presentes. Continuando con la ejecución."
        else
            local joined
            joined=$(printf '%s ' "${MISSING_PY_MODULES[@]}")
            echo "[!] Todavía faltan módulos de Python: ${joined% }"
            echo "    Repite la instalación cuando tengas conectividad o instala paquetes locales."
            exit 1
        fi
    else
        touch .setup_complete
        echo "[+] Dependencias de Python actualizadas correctamente."
    fi
}

# --- Main execution flow ---

detect_os
detect_package_manager

echo "[*] Sistema operativo detectado: $OS_NAME"
echo "[*] Gestor de paquetes detectado: $(package_manager_label)"
if [[ "$OFFLINE_MODE" == "1" ]]; then
    echo "[*] Modo offline habilitado: se omitirán operaciones que requieran acceso a Internet."
fi

resolve_system_dependencies

if [[ ! -d ".venv" ]]; then
    echo "[*] Creando entorno virtual de Python..."
fi
NEED_SETUP=$(setup_virtualenv)

# shellcheck disable=SC1091
source .venv/bin/activate

install_python_dependencies "$NEED_SETUP"

echo "[*] Ejecutando la herramienta..."
python3 main.py "$@"
