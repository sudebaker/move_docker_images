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
from typing import Optional, Dict, List, Tuple

import yaml

# Suprimir warnings de deprecación
warnings.filterwarnings('ignore', category=DeprecationWarning)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Constantes
DEFAULT_TIMEOUT = 600
DISK_CHECK_MB = 1000
DOCKER_SAVE_TIMEOUT = 300
SPINNER_DELAY = 0.1


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
            time.sleep(SPINNER_DELAY)

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


def parse_docker_compose(docker_compose_path: pathlib.Path) -> Tuple[List[Dict], Dict]:
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


def generate_registry_compose(compose_data: Dict, images_info: List[Dict],
                              registry_url: str, prefix: str,
                              output_path: pathlib.Path) -> None:
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
            f.write("# Generado automáticamente por move_images.py\n")
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


def get_all_local_images(exclude_registries: Optional[List[str]] = None,
                         auto_exclude_registries: bool = True) -> List[Dict]:
    """Obtiene todas las imágenes locales del sistema.

    Args:
        exclude_registries: Lista de registries a excluir (ej: ['git.ucosistemas.gc'])
        auto_exclude_registries: Si True, detecta y excluye automáticamente imágenes duplicadas
                                 que tienen una versión sin registry
    """
    try:
        result = subprocess.run(
            ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'],
            capture_output=True, text=True, check=True)

        all_lines = [line for line in result.stdout.strip().split('\n')
                     if line and '<none>' not in line]

        # Si auto_exclude_registries está activo, detectar duplicados
        base_images_set = set()  # Conjunto de imágenes base (sin registry)
        if auto_exclude_registries:
            # Primero, identificar imágenes base (sin registry)
            for line in all_lines:
                # Detectar si tiene un registry (contiene un dominio al inicio)
                # Ejemplo: git.ucosistemas.gc/sistemas/ucographrag/backend:latest
                # vs: ucographrag/backend:latest
                parts = line.split('/', 1)
                if len(parts) > 1 and ('.' in parts[0] or ':' in parts[0].split(':')[0]):
                    # Tiene registry, skip por ahora
                    pass
                else:
                    # No tiene registry, es una imagen base
                    base_images_set.add(line)

        images_info = []
        exclude_registries = exclude_registries or []

        for line in all_lines:
            if not line or line.startswith('<none>'):
                continue

            # Excluir imágenes de registries específicos manualmente especificados
            should_exclude = False
            for registry in exclude_registries:
                if line.startswith(f"{registry}/"):
                    should_exclude = True
                    break

            # Auto-excluir si es una imagen con registry y existe la versión base
            if auto_exclude_registries and not should_exclude:
                parts = line.split('/', 1)
                if len(parts) > 1 and ('.' in parts[0] or ':' in parts[0].split(':')[0]):
                    # Tiene registry, verificar si existe versión base
                    rest = parts[1]
                    if '/' in rest:
                        potential_base = '/'.join(rest.split('/')[1:])
                        # Si existe la versión base (sin registry), excluir esta
                        if potential_base in base_images_set:
                            should_exclude = True

            if not should_exclude:
                images_info.append({
                    'name': line,
                    'service': None,
                    'built': False,  # No podemos saber si fue built sin docker-compose
                    'compose_image': line
                })
        return images_info
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al listar imágenes: {e}")
        return []


def image_exists(image: str) -> bool:
    """Verifica si la imagen existe localmente."""
    try:
        subprocess.run(['docker', 'inspect', image],
                       check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False


def check_disk_space(output_dir: pathlib.Path, required_mb: int = DISK_CHECK_MB) -> bool:
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


def generate_safe_filename(image: str, service_name: Optional[str] = None) -> str:
    """Genera un nombre de archivo seguro y legible para una imagen.

    Args:
        image: Nombre de la imagen (puede ser name:tag o sha256:hash)
        service_name: Nombre del servicio si está disponible

    Returns:
        Nombre de archivo seguro para .tar
    """
    # Si tenemos el nombre del servicio, usarlo como base
    if service_name:
        base = service_name.replace('/', '_').replace(':', '_')
        # Agregar tag si la imagen lo tiene
        if ':' in image and not image.startswith('sha256:'):
            tag = image.split(':')[-1]
            return f"{base}_{tag}.tar"
        return f"{base}_latest.tar"

    # Si es una imagen con SHA256, usar una versión corta más legible
    if image.startswith('sha256:'):
        # Usar solo los primeros 12 caracteres del hash
        short_hash = image.replace('sha256:', '')[:12]
        return f"image_{short_hash}.tar"

    # Caso normal: nombre:tag
    return image.replace('/', '_').replace(':', '_') + ".tar"


def load_metadata(metadata_path: pathlib.Path) -> Dict:
    """Lee metadata previa de imágenes si existe."""
    if not metadata_path.exists():
        return {}
    try:
        return json.loads(metadata_path.read_text())
    except Exception as e:
        logging.warning(
            f"No se pudo leer metadata previa ({metadata_path}): {e}")
        return {}


def save_metadata(metadata_path: pathlib.Path, metadata: Dict) -> None:
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

        subprocess.run(cmd, input=password.encode(),
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
    """Genera tag para el registry usando nombre del servicio o compose_image.

    Para Gitea: registry_url debe ser 'gitea.example.com' y prefix debe ser 'usuario/proyecto'
    Ejemplo: gitea.example.com/miusuario/miproyecto/imagen:tag
    """
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

    # Gitea específico: limpiar nombres para evitar problemas
    # Gitea no acepta bien algunos caracteres en nombres de imagen
    registry_name = registry_name.lower().replace('_', '-')

    # Construir tag completo
    if prefix:
        # Para Gitea: prefix es usuario/proyecto
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


def verify_image_in_registry(registry_tag: str) -> bool:
    """Verifica si la imagen existe en el registry haciendo un pull dry-run."""
    try:
        # Intenta inspeccionar el manifest sin descargar la imagen
        result = subprocess.run(
            ['docker', 'manifest', 'inspect', registry_tag],
            capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0
    except Exception:
        return False


def push_image_to_registry(image: str, registry_tag: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Tag y push de imagen al registry."""
    try:
        # Tag imagen
        subprocess.run(['docker', 'tag', image, registry_tag],
                       check=True, capture_output=True)

        # Push imagen con spinner
        spinner = Spinner(f"Pushing {image}")
        spinner.start()
        try:
            subprocess.run(
                ['docker', 'push', registry_tag],
                capture_output=True, text=True,
                check=True, timeout=timeout
            )
            spinner.stop()
        except Exception:
            spinner.stop()
            raise

        # Verificar que la imagen está realmente en el registry
        verified = verify_image_in_registry(registry_tag)
        if not verified:
            logging.warning(
                f"No se pudo verificar {registry_tag} en registry")

        # Limpiar el tag local del registry después del push
        try:
            subprocess.run(['docker', 'rmi', registry_tag],
                           capture_output=True, check=False)
        except Exception:
            pass

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
                             timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Pull imagen desde registry y re-tag a nombre original."""
    try:
        # Pull imagen con spinner
        spinner = Spinner(f"Pulling {registry_tag}")
        spinner.start()
        try:
            subprocess.run(
                ['docker', 'pull', registry_tag],
                capture_output=True, text=True,
                check=True, timeout=timeout
            )
            spinner.stop()
        except Exception:
            spinner.stop()
            raise

        # Re-tag a nombre original
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
        stderr = e.stderr.lower() if e.stderr else ""
        if 'manifest unknown' in stderr or 'not found' in stderr:
            logging.error(f"Imagen no encontrada: {registry_tag}")
        elif 'unauthorized' in stderr or '401' in stderr:
            logging.error(f"Error de autenticación: {registry_tag}")
        elif 'denied' in stderr or '403' in stderr:
            logging.error(f"Permisos denegados: {registry_tag}")
        else:
            logging.error(
                f"Error al pull {registry_tag}: {e.stderr if e.stderr else str(e)}")
        return False
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout al pull de {registry_tag}")
        return False


# ============================================================================
# ORQUESTADORES PUSH/PULL
# ============================================================================

def push_images(images: List[Dict], registry_url: str, prefix: str,
                skip_unchanged: bool, metadata_path: pathlib.Path,
                only_built: bool, timeout: int = DEFAULT_TIMEOUT) -> Dict:
    """Push imágenes al registry con lógica de skip y metadata."""
    metadata = load_metadata(metadata_path)
    metadata_changed = False

    stats = {'pushed': 0, 'skipped': 0, 'failed': 0, 'not_found': 0}

    for idx, info in enumerate(images, 1):
        image = info['name']
        progress = f"[{idx}/{len(images)}]"

        if only_built and not info.get('built'):
            print(f"{progress} ⏭️  {image} (solo construidas)")
            stats['skipped'] += 1
            continue

        if not image_exists(image):
            print(f"{progress} ❌ {image} (no existe)")
            stats['not_found'] += 1
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
                print(f"{progress} ⏭️  {image} (sin cambios)")
                stats['skipped'] += 1
                continue

        # Push
        if push_image_to_registry(image, registry_tag, timeout):
            print(f"{progress} ✅ {image}")
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
            stats['pushed'] += 1
        else:
            print(f"{progress} ❌ {image} (error)")
            metadata[image] = metadata.get(image, {})
            metadata[image]['push_status'] = 'failed'
            metadata[image]['failed_at'] = datetime.now(
                timezone.utc).isoformat(timespec='seconds')
            metadata_changed = True
            stats['failed'] += 1

    if metadata_changed:
        save_metadata(metadata_path, metadata)

    return stats


def pull_images(metadata_path: pathlib.Path, timeout: int = DEFAULT_TIMEOUT) -> Dict:
    """Pull imágenes desde registry usando metadata."""
    metadata = load_metadata(metadata_path)

    if not metadata:
        print(f"❌ No hay metadata en {metadata_path}")
        return {'pulled': 0, 'skipped': 0, 'failed': 0}

    stats = {'pulled': 0, 'skipped': 0, 'failed': 0}
    items = list(metadata.items())

    print(f"\n📦 Descargando {len(items)} imágenes desde registry...\n")
    for idx, (image, info) in enumerate(items, 1):
        progress = f"[{idx}/{len(items)}]"
        registry_tag = info.get('registry_tag')
        if not registry_tag:
            print(f"{progress} ⏭️  {image} (sin registry_tag)")
            stats['skipped'] += 1
            continue

        if pull_image_from_registry(registry_tag, image, timeout):
            print(f"{progress} ✅ {image}")
            stats['pulled'] += 1
        else:
            print(f"{progress} ❌ {image} (error)")
            stats['failed'] += 1

    return stats


def save_images(images: List[Dict], output_dir: pathlib.Path,
                skip_unchanged: bool, metadata_path: pathlib.Path,
                only_built: bool) -> Dict:
    """Guarda las imágenes en archivos .tar en el directorio especificado."""
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n📂 Directorio de salida: {output_dir}\n")

    metadata = load_metadata(metadata_path)
    metadata_changed = False
    stats = {'saved': 0, 'skipped': 0, 'failed': 0, 'not_found': 0}

    for idx, info in enumerate(images, 1):
        image = info['name']
        progress = f"[{idx}/{len(images)}]"

        if only_built and not info.get('built'):
            print(f"{progress} ⏭️  {image} (solo construidas)")
            stats['skipped'] += 1
            continue
        if not image_exists(image):
            print(f"{progress} ❌ {image} (no existe)")
            stats['not_found'] += 1
            continue
        if not check_disk_space(output_dir, 1000):
            print(f"{progress} ❌ {image} (sin espacio)")
            stats['failed'] += 1
            break

        filename = generate_safe_filename(image, info.get('service'))
        file_path = output_dir / filename
        image_id = get_image_id(image)
        if skip_unchanged and image_id:
            previous = metadata.get(image)
            if previous and previous.get('id') == image_id and file_path.exists():
                print(f"{progress} ⏭️  {image} (sin cambios)")
                stats['skipped'] += 1
                continue

        spinner = Spinner(f"Guardando {image}")
        spinner.start()
        try:
            subprocess.run(
                ['docker', 'save', '-o', str(file_path), image], check=True, timeout=DOCKER_SAVE_TIMEOUT)
            spinner.stop()
            print(f"{progress} ✅ {image}")
            metadata[image] = {
                'id': image_id,
                'tar': str(file_path),
                'built': info.get('built', False),
                'service': info.get('service'),
                'saved_at': datetime.now(timezone.utc).isoformat(timespec='seconds')
            }
            metadata_changed = True
            stats['saved'] += 1
        except subprocess.CalledProcessError as e:
            spinner.stop()
            print(f"{progress} ❌ {image} (error)")
            logging.error(f"Error al guardar {image}: {e}")
            stats['failed'] += 1
        except subprocess.TimeoutExpired:
            spinner.stop()
            print(f"{progress} ❌ {image} (timeout)")
            stats['failed'] += 1

    if metadata_changed:
        save_metadata(metadata_path, metadata)

    return stats


def load_images(input_dir: pathlib.Path) -> Dict:
    """Carga todas las imágenes .tar del directorio especificado."""
    if not input_dir.exists():
        raise RuntimeError(f"El directorio de entrada no existe: {input_dir}")

    files = list(input_dir.glob('*.tar'))
    stats = {'loaded': 0, 'failed': 0}

    print(f"\n📥 Cargando {len(files)} imágenes...\n")
    for idx, file_path in enumerate(files, 1):
        progress = f"[{idx}/{len(files)}]"
        spinner = Spinner(f"Cargando {file_path.name}")
        spinner.start()
        try:
            subprocess.run(
                ['docker', 'load', '-i', str(file_path)], check=True, timeout=DOCKER_SAVE_TIMEOUT)
            spinner.stop()
            print(f"{progress} ✅ {file_path.name}")
            stats['loaded'] += 1
        except subprocess.CalledProcessError as e:
            spinner.stop()
            print(f"{progress} ❌ {file_path.name} (error)")
            logging.error(f"Error: {e}")
            stats['failed'] += 1
        except subprocess.TimeoutExpired:
            spinner.stop()
            print(f"{progress} ❌ {file_path.name} (timeout)")
            stats['failed'] += 1

    return stats


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
    parser.add_argument('--exclude-registry', action='append', dest='exclude_registries',
                        help="Excluir imágenes de este registry al usar save sin docker-compose (puede repetirse)")
    parser.add_argument('--metadata-file', dest='metadata_file',
                        help="Ruta al archivo JSON con metadata. Por defecto: output-dir/image_metadata.json")
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f"Timeout en segundos para operaciones (default: {DEFAULT_TIMEOUT})")

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
        if not args.docker_compose:
            logging.error("--docker-compose es requerido para push/pull")
            sys.exit(1)
    else:  # disk mode (save/load)
        if not args.output_dir:
            logging.error("--output-dir es requerido para save/load")
            sys.exit(1)
        if not args.docker_compose:
            logging.error("--docker-compose es requerido para save/load")
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

        if args.docker_compose:
            # Usar imágenes del docker-compose
            docker_compose_path = pathlib.Path(args.docker_compose)
            images, _ = parse_docker_compose(docker_compose_path)
        else:
            # Usar todas las imágenes locales
            print(
                "ℹ️  No se especificó docker-compose, guardando todas las imágenes locales")
            check_docker_available()

            # Detectar registries a excluir del config, args o --exclude-registry
            exclude_registries = []
            if loaded_config.get('registry_url'):
                exclude_registries.append(loaded_config.get('registry_url'))
            if args.registry_url:
                exclude_registries.append(args.registry_url)
            if args.exclude_registries:
                exclude_registries.extend(args.exclude_registries)

            # Eliminar duplicados
            exclude_registries = list(set(exclude_registries))

            if exclude_registries:
                print(
                    f"🚫 Excluyendo imágenes de: {', '.join(exclude_registries)}")

            images = get_all_local_images(exclude_registries)
            if not images:
                print("❌ No se encontraron imágenes locales")
                sys.exit(1)

        stats = save_images(images, output_dir, args.skip_unchanged,
                            metadata_path, args.only_built)

        # Resumen
        print("\n" + "=" * 50)
        print("📊 Resumen:")
        print(f"   ✅ Guardadas:  {stats['saved']}")
        print(f"   ⏭️  Saltadas:   {stats['skipped']}")
        print(f"   ❌ Fallidas:   {stats['failed']}")
        if stats['not_found'] > 0:
            print(f"   🚫 No encontradas: {stats['not_found']}")
        print(f"   📄 Metadata: {metadata_path}")
        print("=" * 50)

    elif args.action == 'load':
        output_dir = pathlib.Path(args.output_dir)
        stats = load_images(output_dir)

        # Resumen
        print("\n" + "=" * 50)
        print("📊 Resumen:")
        print(f"   ✅ Cargadas:   {stats['loaded']}")
        print(f"   ❌ Fallidas:   {stats['failed']}")
        print("=" * 50)

    elif args.action == 'push':
        if not args.docker_compose:
            print("❌ Error: --docker-compose es requerido para la acción 'push'")
            sys.exit(1)
        # Cargar config si existe para obtener registry_url y prefix
        registry_url = args.registry_url or loaded_config.get(
            'registry_url', '')
        registry_prefix = args.registry_prefix or loaded_config.get(
            'prefix', '')

        print("\n" + "=" * 60)
        print("🐳 Docker Registry Push Tool")
        print("=" * 60)
        print(f"📍 Registry: {registry_url}")
        print(f"📦 Prefix: {registry_prefix or '(ninguno)'}")
        print(f"📄 Compose: {args.docker_compose}")
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

        # Push imágenes
        docker_compose_path = pathlib.Path(args.docker_compose)
        images, compose_data = parse_docker_compose(docker_compose_path)
        print(f"📋 Procesando {len(images)} imágenes...\n")
        stats = push_images(images, registry_url, registry_prefix,
                            args.skip_unchanged, metadata_path, args.only_built,
                            args.timeout)

        # Resumen
        print("\n" + "=" * 50)
        print("📊 Resumen:")
        print(f"   ✅ Subidas:    {stats['pushed']}")
        print(f"   ⏭️  Saltadas:   {stats['skipped']}")
        print(f"   ❌ Fallidas:   {stats['failed']}")
        if stats['not_found'] > 0:
            print(f"   🚫 No encontradas: {stats['not_found']}")
        print(f"   📄 Metadata: {metadata_path}")
        print("=" * 50)

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
        stats = pull_images(metadata_path, args.timeout)

        # Resumen
        print("\n" + "=" * 50)
        print("📊 Resumen:")
        print(f"   ✅ Descargadas: {stats['pulled']}")
        print(f"   ⏭️  Saltadas:    {stats['skipped']}")
        print(f"   ❌ Fallidas:    {stats['failed']}")
        print("=" * 50)

        # Logout si se solicitó
        auto_logout = args.auto_logout or config_data.get('auto_logout', False)
        if auto_logout:
            docker_logout(registry_url)


if __name__ == "__main__":
    main()
