# MD-ATACK-BLUETOOTH V9

Esta es una versión refactorizada y mejorada de la herramienta de auditoría de seguridad Bluetooth `md-atack-bluetooth`.

## Mejoras Implementadas

*   **Seguridad:** Se ha eliminado el uso de `os.system` y `shell=True` para prevenir vulnerabilidades de inyección de comandos.
*   **Manejo de Errores:** Se ha mejorado la gestión de errores para proporcionar feedback más claro y fiable.
*   **Estructura del Código:** El código ha sido refactorizado a un enfoque orientado a objetos para mayor claridad, modularidad y facilidad de mantenimiento.
*   **Gestión de Dependencias:** El lanzador detecta automáticamente el sistema operativo, valida las dependencias (incluyendo Python) y ofrece instalarlas por ti de forma segura.
*   **Interfaz de Línea de Comandos (CLI):** Se ha añadido una interfaz de línea de comandos con `argparse` para un uso más flexible y no interactivo.

## Requisitos y Configuración

1. Da permisos de ejecución al lanzador la primera vez (opcional):
    ```bash
    chmod +x run.sh
    ```
2. Ejecuta `./run.sh` (o `bash run.sh`) con el comando deseado. El script detectará tu distribución Linux, verificará que existan todas las dependencias y te mostrará cualquier carencia.
    * Para aceptar automáticamente la instalación de paquetes soportada (`apt`, `dnf/yum`, `pacman`, `zypper`), exporta `ALLOW_SYSTEM_INSTALL=1`.
    * Para forzar la instalación manual, usa `SKIP_SYSTEM_INSTALL=1`.
    * Si debes operar sin conexión, exporta `OFFLINE_MODE=1`. La herramienta intentará instalar los paquetes Python desde `offline-packages/` (personalizable mediante `OFFLINE_WHEEL_DIR`). Copia allí las ruedas necesarias (`PyOBEX`, `pybluez`, etc.) antes de ejecutar.
3. Una vez resuelto lo anterior, se creará (o reutilizará) el entorno virtual de Python y se instalarán los paquetes listados en `requirements.txt`.
4. Todas las acciones se registran en `audit_log.txt` con detalles de cada comando utilizado.

## Uso

Para usar la herramienta, simplemente ejecuta el script `run.sh` seguido del comando que desees. El script activará el entorno virtual automáticamente.

**Escanear dispositivos:**

```bash
./run.sh scan
```

**Obtener información de un dispositivo:**

```bash
./run.sh info --target-mac <MAC_ADDRESS>
```

**Realizar un ataque de denegación de servicio (DoS):**

```bash
./run.sh dos --target-mac <MAC_ADDRESS> --threads 50 --duration 120
```
Puedes omitir `--duration` si prefieres detener el ataque manualmente con `Ctrl+C`. Añade `--interactive` para ajustar parámetros en el momento; si no se indica, se utilizará un perfil agresivo por defecto.

**Seleccionar adaptador automáticamente (cuando hay varios):**

```bash
./run.sh --auto-select scan
```

**Descargar agenda y contactos:**

```bash
./run.sh get_contacts --target-mac <MAC_ADDRESS>
```

**Enviar un archivo a un dispositivo:**

```bash
./run.sh send-file --target-mac <MAC_ADDRESS> --file /ruta/al/archivo --interactive
```
El modo interactivo permite seleccionar el canal OBEX detectado o ingresar uno manualmente; sin él, la herramienta intenta detectar automáticamente el servicio adecuado y aplica el modo agresivo.

## Pruebas Automatizadas

Se incluye una batería básica de pruebas unitarias para validar la lógica principal (por ejemplo, la orquestación del módulo de lista negra). Ejecuta:

```bash
python -m unittest discover tests
```

Antes de ejecutar estas pruebas en modo offline, asegúrate de tener las dependencias de Python instaladas en el entorno virtual.

**Gestionar la lista negra y ejecutar el ataque automático:**

```bash
./run.sh blacklist --auto-select
```

Durante el flujo se te preguntará si deseas escanear, agregar objetivos (desde el escaneo o manualmente) y confirmar el inicio del ataque. El fichero `blacklist.json` persiste los objetivos; puedes cambiarlo con `--blacklist-file`. El parámetro `--watch-interval` ajusta el intervalo entre escaneos en modo vigilancia.

## Autoría y Licencia

- Autor: **Arnulfo (midesmis)** — contacto: `arnulfoadg@gmail.com` (2024).  
- Licencia: **GNU Affero General Public License v3.0** (`LICENSE`).
- Se permite redistribuir y modificar siempre que se mantenga esta licencia y la atribución correspondiente.

## Uso Ético

La herramienta se diseñó para auditorías y pentesting en entornos controlados con autorización explícita. El uso indebido puede violar leyes locales e internacionales. Utilízala únicamente contra dispositivos de tu propiedad o con consentimiento formal del propietario.

## Contribución y Derivados

1. Mantén los avisos de copyright y la licencia.
2. Documenta claramente tus modificaciones.
3. Envía _pull requests_ con descripciones completas y pruebas asociadas.

Para forks públicos se solicita incluir un enlace visible a este repositorio original para reconocer la autoría de midesmis.
