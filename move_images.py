#!/usr/bin/env python3

import argparse
import json
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time
import warnings
from datetime import datetime, timezone
from typing import Optional

import yaml

# Suprimir warnings de deprecación
warnings.filterwarnings('ignore', category=DeprecationWarning)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')


class Spinner:
    """Spinner animado para operaciones largas."""

    def __init__(self, message: str = "Procesando"):
        self.message = message
        self.running = False
        self.thread = None
        self.frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

    def _spin(self):
        i = 0
        while self.running:
            frame = self.frames[i % len(self.frames)]
            print(f'\r{frame} {self.message}', end='', flush=True)
            i += 1
            time.sleep(0.1)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()

    def stop(self, final_message: str = ""):
        self.running = False
        if self.thread:
            self.thread.join()
        # Limpiar la línea
        print(f'\r{" " * (len(self.message) + 5)}\r', end='', flush=True)
        if final_message:
            print(final_message)


def check_docker_available():
    """Verifica si Docker y Docker Compose están disponibles."""
    try:
        subprocess.run(['docker', 'info'], check=True, capture_output=True)
        subprocess.run(['docker-compose', '--version'],
                       check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        logging.error("Docker o Docker Compose no están disponibles.")
        return False


def parse_docker_compose(docker_compose_path: pathlib.Path) -> tuple[list[dict], dict]:
    """Obtiene información de imágenes y si provienen de build.
    Retorna (images_info, compose_data)."""
    try:
        compose_data = yaml.safe_load(docker_compose_path.read_text())
    except Exception as e:
        raise RuntimeError(
            f"Error al leer el archivo docker-compose.yml: {e}")

    services_cfg = compose_data.get('services', {})
    services_with_build = {
        name: bool(cfg.get('build'))
        for name, cfg in services_cfg.items()
    }

    # Crear mapa de container_name -> service_name real
    container_to_service = {}
    for service_name, cfg in services_cfg.items():
        # container_name puede estar explícito o ser el nombre del servicio
        cont_name = cfg.get('container_name', service_name)
        container_to_service[cont_name] = service_name

    try:
        result = subprocess.run(
            ['docker-compose', '-f',
                str(docker_compose_path), 'images', '--format', 'json'],
            capture_output=True, text=True, check=True
        )
        images_data = yaml.safe_load(result.stdout) or []
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error al ejecutar docker-compose images: {e}")
    except Exception as e:
        raise RuntimeError(
            f"Error al parsear la salida de docker-compose: {e}")

    images_info = []
    for item in images_data:
        repo = item.get('Repository') or ''
        tag = item.get('Tag') or ''
        if repo and tag:
            image_name = f"{repo}:{tag}"
        else:
            image_name = repo or item.get('Image')
        if not image_name:
            continue
        container_name = item.get('ContainerName') or item.get('Service') or ''

        # Buscar el servicio real usando el mapa
        service_name = container_to_service.get(container_name, container_name)
        service_cfg = services_cfg.get(service_name, {})
        compose_image = service_cfg.get('image', '')

        images_info.append({
            'name': image_name,
            'service': service_name,
            'built': services_with_build.get(service_name, False),
            'compose_image': compose_image
        })
    return images_info, compose_data


def generate_registry_compose(compose_data: dict, images_info: list[dict],
                              registry_url: str, prefix: str,
                              output_path: pathlib.Path):
    """Genera un nuevo docker-compose.yml con imágenes del registry."""
    import copy
    from datetime import datetime, timezone

    new_compose = copy.deepcopy(compose_data)
    services = new_compose.get('services', {})

    # Crear mapa de service_name -> registry_tag
    service_to_registry_tag = {}
    for info in images_info:
        service_name = info.get('service')
        if service_name:
            registry_tag = generate_registry_tag(
                info['name'], registry_url, prefix,
                service_name=service_name,
                compose_image=info.get('compose_image', '')
            )
            service_to_registry_tag[service_name] = registry_tag

    # Actualizar servicios
    modified_services = []
    for service_name, service_cfg in services.items():
        if service_name in service_to_registry_tag:
            # Reemplazar image
            service_cfg['image'] = service_to_registry_tag[service_name]
            modified_services.append(service_name)

            # Eliminar build si existe
            if 'build' in service_cfg:
                del service_cfg['build']

            # Cambiar pull_policy si existía como 'never'
            if service_cfg.get('pull_policy') == 'never':
                service_cfg['pull_policy'] = 'always'

    # Guardar nuevo compose
    try:
        with open(output_path, 'w') as f:
            # Escribir comentario de generación
            timestamp = datetime.now(timezone.utc).strftime(
                '%Y-%m-%d %H:%M:%S UTC')
            f.write(f"# Generado automáticamente por move_images.py\n")
            f.write(f"# Fecha: {timestamp}\n")
            f.write(f"# Registry: {registry_url}\n")
            f.write(
                f"# Servicios modificados: {', '.join(modified_services)}\n\n")

            # Escribir YAML
            yaml.dump(new_compose, f, default_flow_style=False, sort_keys=False)

        print(f"✅ Nuevo docker-compose generado: {output_path}")
        print(
            f"   📦 {len(modified_services)} servicios actualizados con imágenes del registry")
    except Exception as e:
        print(f"❌ Error al generar docker-compose: {e}")


def image_exists(image: str) -> bool:
    """Verifica si la imagen existe localmente."""
    try:
        subprocess.run(['docker', 'inspect', image],
                       check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False


def check_disk_space(output_dir: pathlib.Path, required_mb: int = 1000) -> bool:
    """Verifica si hay suficiente espacio en disco (en MB)."""
    try:
        stat = shutil.disk_usage(output_dir)
        available_mb = stat.free / (1024 ** 3) * 1000  # Convertir a MB
        if available_mb < required_mb:
            logging.error(
                f"Espacio insuficiente en {output_dir}: {available_mb:.2f} MB disponibles, se necesitan al menos {required_mb} MB.")
            return False
        return True
    except Exception as e:
        logging.error(f"Error al verificar espacio en disco: {e}")
        return False


def load_metadata(metadata_path: pathlib.Path) -> dict:
    """Lee metadata previa de imágenes si existe."""
    if not metadata_path.exists():
        return {}
    try:
        return json.loads(metadata_path.read_text())
    except Exception as e:
        logging.warning(
            f"No se pudo leer metadata previa ({metadata_path}): {e}")
        return {}


def save_metadata(metadata_path: pathlib.Path, metadata: dict):
    """Guarda metadata actualizada."""
    try:
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(json.dumps(metadata, indent=2))
    except Exception as e:
        logging.error(f"No se pudo guardar metadata en {metadata_path}: {e}")


def get_image_id(image: str) -> Optional[str]:
    """Devuelve el ID interno de la imagen."""
    try:
        result = subprocess.run(
            ['docker', 'inspect', '--format', '{{.Id}}', image],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


# ============================================================================
# FUNCIONES DE AUTENTICACIÓN REGISTRY
# ============================================================================

def check_existing_docker_login(registry_url: str) -> bool:
    """Verifica si existe login válido en config de Docker."""
    config_path = pathlib.Path.home() / '.docker' / 'config.json'
    if not config_path.exists():
        return False

    try:
        config = json.loads(config_path.read_text())
        auths = config.get('auths', {})
        # Registry puede estar con o sin http(s)://
        for key in [registry_url, f"http://{registry_url}",
                    f"https://{registry_url}"]:
            if key in auths:
                return True
        return False
    except Exception as e:
        logging.warning(f"Error al leer config de Docker: {e}")
        return False


def docker_login(registry_url: str, username: str, password: str) -> bool:
    """Ejecuta docker login."""
    try:
        cmd = ['docker', 'login', registry_url,
               '-u', username, '--password-stdin']

        result = subprocess.run(cmd, input=password.encode(),
                                capture_output=True, check=True)
        print(f"✔️  Login exitoso en {registry_url}")
        return True
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode() if e.stderr else str(e)
        logging.error(f"Error en login: {error_msg}")
        return False


def docker_logout(registry_url: str):
    """Ejecuta docker logout."""
    try:
        subprocess.run(['docker', 'logout', registry_url],
                       capture_output=True, check=True)
        # Logout silencioso
        pass
    except subprocess.CalledProcessError as e:
        logging.warning(f"Error en logout: {e}")


def test_registry_public_access(registry_url: str) -> bool:
    """Verifica si el registry permite acceso sin auth."""
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{registry_url}/v2/_catalog"
            result = subprocess.run(['curl', '-s', '-o', '/dev/null',
                                     '-w', '%{http_code}', url],
                                    capture_output=True, text=True, timeout=5)
            if result.stdout.strip() == '200':
                return True
        except Exception:
            continue
    return False


def load_registry_config(config_path: pathlib.Path) -> dict:
    """Carga configuración del registry desde JSON."""
    if not config_path.exists():
        raise FileNotFoundError(f"Config no encontrado: {config_path}")

    # Verificar permisos en sistemas Unix
    if hasattr(os, 'stat') and (config_path.stat().st_mode & 0o077):
        logging.warning(
            f"Advertencia: {config_path} tiene permisos inseguros. "
            f"Ejecuta: chmod 600 {config_path}"
        )

    return json.loads(config_path.read_text())


def ensure_registry_auth(registry_url: str, user: Optional[str] = None,
                         password: Optional[str] = None,
                         config_file: Optional[pathlib.Path] = None,
                         skip_login: bool = False) -> tuple[bool, dict]:
    """Asegura que hay autenticación válida para el registry.
    Retorna (success, config_data) donde config_data contiene configuración cargada."""
    config_data = {}

    if skip_login:
        print("⏭️  Saltando verificación de autenticación")
        return True, config_data

    # 1. Check existing login
    if check_existing_docker_login(registry_url):
        print(f"✔️  Usando login existente para {registry_url}")
        return True, config_data

    # 2. Try config file first (prioridad)
    if config_file:
        try:
            config_data = load_registry_config(config_file)
            user = user or config_data.get('username')
            password = password or config_data.get('password')
        except Exception as e:
            logging.warning(f"No se pudo cargar config: {e}")

    # 3. Try env vars
    if not user:
        user = os.environ.get('REGISTRY_USER')
    if not password:
        password = os.environ.get('REGISTRY_PASSWORD')

    # 4. Perform login if credentials available
    if user and password:
        success = docker_login(registry_url, user, password)
        return success, config_data

    # 5. No credentials - test if registry is public
    if test_registry_public_access(registry_url):
        print(f"ℹ️  Registry {registry_url} no requiere autenticación")
        return True, config_data

    # 6. Auth required but not provided
    logging.error(f"Registry {registry_url} requiere autenticación.")
    logging.error("Opciones:")
    logging.error("  1. Ejecuta: docker login {registry_url}")
    logging.error("  2. Usa: --registry-user y --registry-password")
    logging.error("  3. Define: REGISTRY_USER y REGISTRY_PASSWORD")
    logging.error("  4. Usa: --registry-config <archivo.json>")
    return False, config_data


# ============================================================================
# FUNCIONES DE REGISTRY (TAG, PUSH, PULL)
# ============================================================================

def check_registry_available(registry_url: str) -> bool:
    """Verifica conectividad con el registry."""
    # Intentar HTTPS primero, luego HTTP
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{registry_url}/v2/"
            result = subprocess.run(['curl', '-s', '-o', '/dev/null',
                                     '-w', '%{http_code}', url],
                                    capture_output=True, text=True, timeout=10)
            code = result.stdout.strip()
            if code in ['200', '401', '403']:  # 401/403 = requiere auth pero está disponible
                print(
                    f"✔️  Registry {registry_url} disponible ({protocol.upper()})")
                return True
        except Exception:
            continue

    logging.error(f"Registry {registry_url} no disponible")
    return False


def generate_registry_tag(image: str, registry_url: str, prefix: str = "",
                          service_name: str = "", compose_image: str = "") -> str:
    """Genera tag para el registry usando nombre del servicio o compose_image."""
    # Extraer tag de la imagen actual
    if ':' in image and not image.startswith('sha256:'):
        _, tag = image.rsplit(':', 1)
    else:
        tag = 'latest'

    # Si el tag es un hash SHA256, usar 'latest'
    if tag.startswith('sha256:') or len(tag) == 64:
        tag = 'latest'

    # Determinar el nombre a usar en el registry
    if compose_image:
        # Si hay compose_image (ej: ucographrag/celery-exporter), usarlo tal cual
        # Mantiene la estructura original incluyendo /
        if ':' in compose_image:
            registry_name = compose_image.split(':')[0]
        else:
            registry_name = compose_image
    elif service_name:
        # Normalizar nombre del servicio (- a _) para compatibilidad Docker
        registry_name = service_name.replace('-', '_')
    else:
        # Fallback: sanitizar el nombre de la imagen actual
        if ':' in image and not image.startswith('sha256:'):
            name = image.split(':')[0]
        else:
            # Usar primeros 12 chars del hash
            name = image.replace('sha256:', '')[:12]
        registry_name = name.replace('/', '_').replace('.', '_')

    # Construir tag completo
    if prefix:
        registry_tag = f"{registry_url}/{prefix}/{registry_name}:{tag}"
    else:
        registry_tag = f"{registry_url}/{registry_name}:{tag}"

    return registry_tag


def get_image_digest(registry_tag: str) -> Optional[str]:
    """Devuelve el digest del manifest de la imagen."""
    try:
        result = subprocess.run(
            ['docker', 'inspect', '--format',
                '{{index .RepoDigests 0}}', registry_tag],
            capture_output=True, text=True, check=True
        )
        digest = result.stdout.strip()
        return digest if digest else None
    except subprocess.CalledProcessError:
        return None


def push_image_to_registry(image: str, registry_tag: str, timeout: int = 600) -> bool:
    """Tag y push de imagen al registry."""
    try:
        # Tag imagen
        print(f"🏷️  Tagging {image} -> {registry_tag}")
        subprocess.run(['docker', 'tag', image, registry_tag],
                       check=True, capture_output=True)

        # Push imagen con spinner
        spinner = Spinner(f"⬆️  Pushing {registry_tag}")
        spinner.start()
        try:
            result = subprocess.run(
                ['docker', 'push', registry_tag],
                capture_output=True, text=True,
                check=True, timeout=timeout
            )
            spinner.stop(f"✅ Push exitoso: {registry_tag}")
        except:
            spinner.stop()
            raise
        return True
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.lower() if e.stderr else ""
        if 'unauthorized' in stderr or '401' in stderr:
            logging.error(f"Error de autenticación al subir {image}")
            logging.error("Verifica credenciales con: docker login")
        elif 'denied' in stderr or '403' in stderr:
            logging.error(f"Permisos denegados para {image}")
        elif 'not found' in stderr or 'unknown' in stderr:
            logging.error(f"Error al push: {e.stderr if e.stderr else e}")
            logging.error(f"El registry rechazó la imagen {registry_tag}")
            logging.error("Posibles causas:")
            logging.error(
                "  1. Falta namespace/proyecto: usa --registry-prefix <namespace>")
            logging.error("  2. El proyecto no existe en el registry")
            logging.error("  3. No tienes permisos de push en ese namespace")
        else:
            logging.error(f"Error al push: {e.stderr if e.stderr else e}")
        return False
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout al push de {registry_tag}")
        return False


def pull_image_from_registry(registry_tag: str, original_name: str,
                             timeout: int = 600) -> bool:
    """Pull imagen desde registry y re-tag a nombre original."""
    try:
        # Pull imagen con spinner
        spinner = Spinner(f"⬇️  Pulling {registry_tag}")
        spinner.start()
        try:
            subprocess.run(
                ['docker', 'pull', registry_tag],
                capture_output=True, text=True,
                check=True, timeout=timeout
            )
            spinner.stop(f"✅ Pull exitoso: {registry_tag}")
        except:
            spinner.stop()
            raise

        # Re-tag a nombre original
        print(f"🏷️  Re-tagging -> {original_name}")
        subprocess.run(['docker', 'tag', registry_tag, original_name],
                       check=True, capture_output=True)

        # Limpieza opcional del tag de registry
        try:
            subprocess.run(['docker', 'rmi', registry_tag],
                           capture_output=True)
        except Exception:
            pass  # No crítico si falla

        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error al pull: {e.stderr if e.stderr else e}")
        return False
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout al pull de {registry_tag}")
        return False


# ============================================================================
# ORQUESTADORES PUSH/PULL
# ============================================================================

def push_images(images: list[dict], registry_url: str, prefix: str,
                skip_unchanged: bool, metadata_path: pathlib.Path,
                only_built: bool, timeout: int = 600):
    """Push imágenes al registry con lógica de skip y metadata."""
    metadata = load_metadata(metadata_path)
    metadata_changed = False

    for info in images:
        image = info['name']
        if only_built and not info.get('built'):
            print(f"⏭️  Saltando {image} (solo imágenes construidas)")
            continue

        if not image_exists(image):
            print(f"❌ Imagen {image} no existe localmente. Saltando.")
            continue

        registry_tag = generate_registry_tag(
            image, registry_url, prefix,
            service_name=info.get('service', ''),
            compose_image=info.get('compose_image', '')
        )
        image_id = get_image_id(image)

        # Skip unchanged
        if skip_unchanged and image_id:
            previous = metadata.get(image)
            if previous and previous.get('id') == image_id:
                print(f"⏭️  Sin cambios en {image}. Saltando push.")
                continue

        # Push
        if push_image_to_registry(image, registry_tag, timeout):
            digest = get_image_digest(registry_tag)
            metadata[image] = {
                'id': image_id,
                'registry_tag': registry_tag,
                'digest': digest,
                'built': info.get('built', False),
                'service': info.get('service'),
                'pushed_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                'push_status': 'success'
            }
            metadata_changed = True
        else:
            metadata[image] = metadata.get(image, {})
            metadata[image]['push_status'] = 'failed'
            metadata[image]['failed_at'] = datetime.now(
                timezone.utc).isoformat(timespec='seconds')
            metadata_changed = True

    if metadata_changed:
        save_metadata(metadata_path, metadata)


def pull_images(metadata_path: pathlib.Path, timeout: int = 600):
    """Pull imágenes desde registry usando metadata."""
    metadata = load_metadata(metadata_path)

    if not metadata:
        print(f"❌ No hay metadata en {metadata_path}")
        return

    print(f"\n📦 Descargando {len(metadata)} imágenes desde registry...\n")
    for image, info in metadata.items():
        registry_tag = info.get('registry_tag')
        if not registry_tag:
            print(f"⚠️  No hay registry_tag para {image}. Saltando.")
            continue

        pull_image_from_registry(registry_tag, image, timeout)


def save_images(images: list[dict], output_dir: pathlib.Path,
                skip_unchanged: bool, metadata_path: pathlib.Path,
                only_built: bool):
    """Guarda las imágenes en archivos .tar en el directorio especificado."""
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n📂 Directorio de salida: {output_dir}\n")

    metadata = load_metadata(metadata_path)
    metadata_changed = False

    for info in images:
        image = info['name']
        if only_built and not info.get('built'):
            print(f"⏭️  Saltando {image} (solo imágenes construidas)")
            continue
        if not image_exists(image):
            logging.error(f"Imagen {image} no existe localmente. Saltando.")
            continue
        if not check_disk_space(output_dir, 1000):  # Asumir al menos 1GB por imagen
            logging.error("Abortando guardado debido a falta de espacio.")
            break

        filename = image.replace('/', '_').replace(':', '_') + ".tar"
        file_path = output_dir / filename
        image_id = get_image_id(image)
        if skip_unchanged and image_id:
            previous = metadata.get(image)
            if previous and previous.get('id') == image_id and file_path.exists():
                print(f"⏭️  Sin cambios en {image}. Usando copia existente")
                continue

        print(f"📦 Guardando: {image} -> {file_path.name}")
        try:
            subprocess.run(
                ['docker', 'save', '-o', str(file_path), image], check=True, timeout=300)
            metadata[image] = {
                'id': image_id,
                'tar': str(file_path),
                'built': info.get('built', False),
                'service': info.get('service'),
                'saved_at': datetime.now(timezone.utc).isoformat(timespec='seconds')
            }
            metadata_changed = True
        except subprocess.CalledProcessError as e:
            logging.error(f"Error al guardar la imagen {image}: {e}")
        except subprocess.TimeoutExpired:
            logging.error(f"Timeout al guardar la imagen {image}.")

    if metadata_changed:
        save_metadata(metadata_path, metadata)


def load_images(input_dir: pathlib.Path):
    """Carga todas las imágenes .tar del directorio especificado."""
    if not input_dir.exists():
        raise RuntimeError(f"El directorio de entrada no existe: {input_dir}")

    for file_path in input_dir.glob('*.tar'):
        print(f"📥 Cargando: {file_path.name}")
        try:
            subprocess.run(
                ['docker', 'load', '-i', str(file_path)], check=True, timeout=300)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error al cargar la imagen {file_path.name}: {e}")
        except subprocess.TimeoutExpired:
            logging.error(f"Timeout al cargar la imagen {file_path.name}.")


def main():
    parser = argparse.ArgumentParser(
        description="Guardar/cargar imágenes de Docker Compose (disco o registry)")
    parser.add_argument(
        '--action', choices=['save', 'load', 'push', 'pull'], required=True,
        help="Acción: save/load (disco) o push/pull (registry)")
    parser.add_argument('--docker-compose', dest='docker_compose',
                        help="Ruta al archivo docker-compose.yml (requerido para save/push)")
    parser.add_argument('--output-dir',
                        help="Directorio para guardar/cargar imágenes (solo modo disco)")

    # Opciones comunes
    parser.add_argument('--skip-unchanged', action='store_true',
                        help="No vuelve a guardar/push imágenes sin cambios")
    parser.add_argument('--only-built', action='store_true',
                        help="Solo imágenes construidas localmente (servicios con build)")
    parser.add_argument('--metadata-file', dest='metadata_file',
                        help="Ruta al archivo JSON con metadata. Por defecto: output-dir/image_metadata.json")
    parser.add_argument('--timeout', type=int, default=600,
                        help="Timeout en segundos para operaciones (default: 600)")

    # Opciones de registry
    parser.add_argument('--registry-url',
                        help="URL del registry (ej: localhost:5000)")
    parser.add_argument('--registry-prefix', default='',
                        help="Prefijo para organizar imágenes en registry (ej: proyecto)")
    parser.add_argument('--registry-user',
                        help="Usuario para autenticación en registry")
    parser.add_argument('--registry-password',
                        help="Contraseña para autenticación (preferir variables de entorno)")
    parser.add_argument('--registry-config',
                        help="Archivo JSON con configuración de registry")
    parser.add_argument('--skip-login', action='store_true',
                        help="No intentar login (asumir ya autenticado)")
    parser.add_argument('--auto-logout', action='store_true',
                        help="Hacer logout del registry al finalizar")
    parser.add_argument('--generate-compose',
                        help="Generar nuevo docker-compose.yml con imágenes del registry (solo con push)")

    args = parser.parse_args()

    if not check_docker_available():
        sys.exit(1)

    # Determinar modo: disk o registry
    is_registry_mode = args.action in ['push', 'pull']

    # Cargar config si existe (antes de validaciones)
    registry_config_path = pathlib.Path(
        args.registry_config) if args.registry_config else None
    loaded_config = {}
    if registry_config_path:
        try:
            loaded_config = load_registry_config(registry_config_path)
        except Exception as e:
            logging.warning(f"No se pudo cargar registry_config: {e}")

    # Validaciones
    if is_registry_mode:
        registry_url_from_config = loaded_config.get('registry_url')
        if not args.registry_url and not registry_url_from_config:
            logging.error(
                "--registry-url es requerido para push/pull (o especificarlo en registry_config)")
            sys.exit(1)
        if args.action == 'push' and not args.docker_compose:
            logging.error("--docker-compose es requerido para push")
            sys.exit(1)
    else:  # disk mode
        if not args.output_dir:
            logging.error("--output-dir es requerido para save/load")
            sys.exit(1)

    # Metadata path
    if args.metadata_file:
        metadata_path = pathlib.Path(args.metadata_file)
    elif args.output_dir:
        metadata_path = pathlib.Path(args.output_dir) / 'image_metadata.json'
    else:
        metadata_path = pathlib.Path.cwd() / 'image_metadata.json'

    # Ejecutar acción
    if args.action == 'save':
        output_dir = pathlib.Path(args.output_dir)
        docker_compose_path = pathlib.Path(args.docker_compose)
        images, _ = parse_docker_compose(docker_compose_path)
        save_images(images, output_dir, args.skip_unchanged,
                    metadata_path, args.only_built)

    elif args.action == 'load':
        output_dir = pathlib.Path(args.output_dir)
        load_images(output_dir)

    elif args.action == 'push':
        # Cargar config si existe para obtener registry_url y prefix
        registry_url = args.registry_url or loaded_config.get(
            'registry_url', '')
        registry_prefix = args.registry_prefix or loaded_config.get(
            'prefix', '')

        print("\n" + "="*60)
        print("🐳 Docker Registry Push Tool")
        print("="*60)
        print(f"📍 Registry: {registry_url}")
        print(f"📦 Prefix: {registry_prefix or '(ninguno)'}")
        print(f"📄 Compose: {args.docker_compose}")
        print("="*60 + "\n")

        # Verificar registry
        if not check_registry_available(registry_url):
            sys.exit(1)

        # Autenticación
        auth_success, config_data = ensure_registry_auth(
            registry_url, args.registry_user,
            args.registry_password, registry_config_path,
            args.skip_login)
        if not auth_success:
            sys.exit(1)

        # Push imágenes
        docker_compose_path = pathlib.Path(args.docker_compose)
        images, compose_data = parse_docker_compose(docker_compose_path)
        print(f"📋 Procesando {len(images)} imágenes...\n")
        push_images(images, registry_url, registry_prefix,
                    args.skip_unchanged, metadata_path, args.only_built,
                    args.timeout)
        print(f"\n✨ Proceso completado. Metadata guardado en: {metadata_path}")

        # Generar nuevo docker-compose si se solicitó
        if args.generate_compose:
            output_compose = pathlib.Path(args.generate_compose)
            print("\n📝 Generando docker-compose para registry...")
            generate_registry_compose(compose_data, images, registry_url,
                                      registry_prefix, output_compose)

        # Logout si se solicitó
        auto_logout = args.auto_logout or config_data.get('auto_logout', False)
        if auto_logout:
            docker_logout(registry_url)

    elif args.action == 'pull':
        registry_url = args.registry_url or loaded_config.get(
            'registry_url', '')

        print("\n" + "=" * 60)
        print("🐳 Docker Registry Pull Tool")
        print("=" * 60)
        print(f"📍 Registry: {registry_url}")
        print(f"📄 Metadata: {metadata_path}")
        print("=" * 60 + "\n")

        # Verificar registry
        if not check_registry_available(registry_url):
            sys.exit(1)

        # Autenticación
        auth_success, config_data = ensure_registry_auth(
            registry_url, args.registry_user,
            args.registry_password, registry_config_path,
            args.skip_login)
        if not auth_success:
            sys.exit(1)

        # Pull imágenes
        pull_images(metadata_path, args.timeout)
        print(f"\n✨ Proceso completado!")

        # Logout si se solicitó
        auto_logout = args.auto_logout or config_data.get('auto_logout', False)
        if auto_logout:
            docker_logout(registry_url)


if __name__ == "__main__":
    main()
