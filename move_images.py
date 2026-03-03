#!/usr/bin/env python3

import argparse
import copy
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

warnings.filterwarnings('ignore', category=DeprecationWarning)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Constants for timeouts and disk checks

DEFAULT_TIMEOUT = 600
DISK_CHECK_MB = 1000
DOCKER_SAVE_TIMEOUT = 300
SPINNER_DELAY = 0.1


class Spinner:
    """Animated spinner for long-running operations."""


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
        print(f'\r{" " * (len(self.message) + 5)}\r', end='', flush=True)
        if final_message:
            print(final_message)



def check_docker_available():
    """Verify that Docker and Docker Compose are available."""

    try:
        subprocess.run(['docker', 'info'], check=True, capture_output=True)
        subprocess.run(['docker-compose', '--version'],
                       check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        logging.error("Docker o Docker Compose no están disponibles.")
        return False


def parse_docker_compose(docker_compose_path: pathlib.Path) -> Tuple[List[Dict], Dict]:
    """Parse docker-compose.yml and extract image information and build status.
    
    Returns (images_info, compose_data) tuple.
    """

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

    # Map container_name to service_name for lookup
    container_to_service = {}
    for service_name, cfg in services_cfg.items():
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

        service_name = container_to_service.get(container_name, container_name)
        service_cfg = services_cfg.get(service_name, {})
        compose_image = service_cfg.get('image', '')

        # If compose_image exists and current image is SHA256, prefer compose_image.
        # This ensures docker save uses the correct name instead of hash.
        if compose_image and (repo == 'sha256' or image_name.startswith('sha256:')):
            image_name = compose_image


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
    """Generate a new docker-compose.yml with images from the registry."""
    new_compose = copy.deepcopy(compose_data)
    services = new_compose.get('services', {})

    # Map service_name to registry_tag for efficient lookup
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

    # Update services with registry images
    modified_services = []
    for service_name, service_cfg in services.items():
        if service_name in service_to_registry_tag:
            service_cfg['image'] = service_to_registry_tag[service_name]
            modified_services.append(service_name)

            if 'build' in service_cfg:
                del service_cfg['build']

            if service_cfg.get('pull_policy') == 'never':
                service_cfg['pull_policy'] = 'always'

    # Save generated compose
    try:
        with open(output_path, 'w') as f:
            timestamp = datetime.now(timezone.utc).strftime(
                '%Y-%m-%d %H:%M:%S UTC')
            f.write("# Auto-generated by move_images.py\n")
            f.write(f"# Date: {timestamp}\n")
            f.write(f"# Registry: {registry_url}\n")
            f.write(
                f"# Modified services: {', '.join(modified_services)}\n\n")

            yaml.dump(new_compose, f, default_flow_style=False, sort_keys=False)

        print(f"OK New docker-compose generated: {output_path}")
        print(
            f"   PKG {len(modified_services)} services updated with registry images")
    except Exception as e:
        print(f"FAIL Error generating docker-compose: {e}")



def image_has_registry(image_name: str) -> bool:
    """Detect if an image has a registry in its name.
    
    Examples:
    - 'git.ucosistemas.gc/sistemas/image:tag' -> True (has dot)
    - 'localhost:5000/image:tag' -> True (has port)
    - 'quay.io/image:tag' -> True (has dot)
    - 'myregistry:5000/image:tag' -> True (has port)
    - 'ubuntu:20.04' -> False (no registry)
    - 'myimage/subimage:tag' -> False (no registry)
    """
    if '/' in image_name:
        registry_part = image_name.split('/')[0]
        return '.' in registry_part or ':' in registry_part
    
    return False


def get_all_local_images(exclude_registries: Optional[List[str]] = None,
                         auto_exclude_registries: bool = True) -> List[Dict]:
    """Get all local Docker images on the system.

    Args:
        exclude_registries: List of registries to exclude (e.g., ['git.ucosistemas.gc'])
        auto_exclude_registries: If True, automatically detect and exclude duplicate images
                                 that have a version without registry
    """

    try:
        result = subprocess.run(
            ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'],
            capture_output=True, text=True, check=True)

        all_lines = [line for line in result.stdout.strip().split('\n')
                     if line and '<none>' not in line]

        # Auto-detect duplicates if enabled
        base_images_set = set()
        if auto_exclude_registries:
            # First, identify base images (without registry)
            for line in all_lines:
                if not image_has_registry(line):
                    base_images_set.add(line)

        images_info = []
        exclude_registries = exclude_registries or []

        for line in all_lines:
            if not line or line.startswith('<none>'):
                continue

            # Exclude images from specific manually specified registries
            should_exclude = False
            for registry in exclude_registries:
                if line.startswith(f"{registry}/"):
                    should_exclude = True
                    break

            # Auto-exclude if image has registry and base version exists
            if auto_exclude_registries and not should_exclude:
                if image_has_registry(line):
                    # Extract the part without the registry
                    first_slash = line.find('/')
                    if first_slash != -1:
                        rest = line[first_slash + 1:]
                        if '/' in rest:
                            # Format: registry/org/image:tag -> look for org/image:tag
                            potential_base = '/'.join(rest.split('/')[1:])
                            if potential_base in base_images_set:
                                should_exclude = True

            if not should_exclude:
                images_info.append({
                    'name': line,
                    'service': None,
                    'built': False,
                    'compose_image': line
                })

        return images_info
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al listar imágenes: {e}")
        return []


def image_exists(image: str) -> bool:
    """Check if an image exists locally."""

    try:
        subprocess.run(['docker', 'inspect', image],
                       check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False


def check_disk_space(output_dir: pathlib.Path, required_mb: int = DISK_CHECK_MB) -> bool:
    """Check if there is sufficient disk space (in MB)."""

    try:
        stat = shutil.disk_usage(output_dir)
        available_mb = stat.free / (1024 ** 2)
        if available_mb < required_mb:
            logging.error(
                f"Insufficient disk space in {output_dir}: {available_mb:.2f} MB available, at least {required_mb} MB required.")
            return False
        return True

    except Exception as e:
        logging.error(f"Error al verificar espacio en disco: {e}")
        return False


def generate_safe_filename(image: str, service_name: Optional[str] = None) -> str:
    """Generate a safe and readable filename for an image.

    Args:
        image: Image name (can be name:tag or sha256:hash)
        service_name: Service name if available

    Returns:
        Safe filename for .tar archive
    """
    if service_name:
        base = service_name.replace('/', '_').replace(':', '_')
        if ':' in image and not image.startswith('sha256:'):
            tag = image.split(':')[-1]
            return f"{base}_{tag}.tar"
        return f"{base}_latest.tar"

    if image.startswith('sha256:'):
        short_hash = image.replace('sha256:', '')[:12]
        return f"image_{short_hash}.tar"

    return image.replace('/', '_').replace(':', '_') + ".tar"



def load_metadata(metadata_path: pathlib.Path) -> Dict:
    """Read previous metadata from images if it exists."""

    if not metadata_path.exists():
        return {}
    try:
        return json.loads(metadata_path.read_text())
    except Exception as e:
        logging.warning(
            f"No se pudo leer metadata previa ({metadata_path}): {e}")
        return {}


def save_metadata(metadata_path: pathlib.Path, metadata: Dict) -> None:
    """Save updated metadata with secure permissions (600)."""
    try:
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(json.dumps(metadata, indent=2))
        # Set secure permissions (owner read/write only)
        metadata_path.chmod(0o600)

    except Exception as e:
        logging.error(f"No se pudo guardar metadata en {metadata_path}: {e}")


def get_image_id(image: str) -> Optional[str]:
    """Return the internal ID of the image."""

    try:
        result = subprocess.run(
            ['docker', 'inspect', '--format', '{{.Id}}', image],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


# ============================================================================
# Registry authentication functions
# ============================================================================

def check_existing_docker_login(registry_url: str) -> bool:
    """Check if valid login exists in Docker config."""

    config_path = pathlib.Path.home() / '.docker' / 'config.json'
    if not config_path.exists():
        return False

    try:
        config = json.loads(config_path.read_text())
        auths = config.get('auths', {})
        # Registry may be with or without http(s)://
        for key in [registry_url, f"http://{registry_url}",
                    f"https://{registry_url}"]:
            if key in auths:
                return True
        return False

    except Exception as e:
        logging.warning(f"Error al leer config de Docker: {e}")
        return False


def docker_login(registry_url: str, username: str, password: str) -> bool:
    """Execute docker login."""

    try:
        cmd = ['docker', 'login', registry_url,
               '-u', username, '--password-stdin']

        subprocess.run(cmd, input=password.encode(),
                       capture_output=True, check=True)
        print(f"OK Login successful in {registry_url}")

        return True
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode() if e.stderr else str(e)
        logging.error(f"Error en login: {error_msg}")
        return False


def docker_logout(registry_url: str):
    """Execute docker logout."""
    try:
        subprocess.run(['docker', 'logout', registry_url],
                       capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.warning(f"Error in logout: {e}")



def test_registry_public_access(registry_url: str) -> bool:
    """Check if the registry allows access without authentication."""

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
    """Load registry configuration from JSON file."""
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    # Check permissions on Unix systems
    if hasattr(os, 'stat') and (config_path.stat().st_mode & 0o077):
        logging.warning(
            f"Warning: {config_path} has insecure permissions. "
            f"Run: chmod 600 {config_path}"
        )

    return json.loads(config_path.read_text())



def ensure_registry_auth(registry_url: str, user: Optional[str] = None,
                         password: Optional[str] = None,
                         config_file: Optional[pathlib.Path] = None,
                         skip_login: bool = False) -> tuple[bool, dict]:
    """Ensure valid authentication exists for the registry.
    
    Returns (success, config_data) where config_data contains loaded configuration.
    """
    config_data = {}

    if skip_login:
        print("SKIP Skipping authentication verification")
        return True, config_data

    # 1. Check existing login
    if check_existing_docker_login(registry_url):
        print(f"OK Using existing login for {registry_url}")
        return True, config_data

    # 2. Try config file first (priority)
    if config_file:
        try:
            config_data = load_registry_config(config_file)
            user = user or config_data.get('username')
            password = password or config_data.get('password')
        except Exception as e:
            logging.warning(f"Could not load config: {e}")

    # 3. Try environment variables
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
        print(f"INFO Registry {registry_url} does not require authentication")
        return True, config_data

    # 6. Auth required but not provided
    logging.error(f"Registry {registry_url} requires authentication.")
    logging.error("Options:")
    logging.error(f"  1. Run: docker login {registry_url}")
    logging.error("  2. Use: --registry-user and --registry-password")
    logging.error("  3. Set: REGISTRY_USER and REGISTRY_PASSWORD")
    logging.error("  4. Use: --registry-config <file.json>")
    return False, config_data


# ============================================================================
# Registry functions (tag, push, pull)
# ============================================================================

def check_registry_available(registry_url: str) -> bool:
    """Check connectivity to the registry."""
    # Try HTTPS first, then HTTP
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{registry_url}/v2/"
            result = subprocess.run(['curl', '-s', '-o', '/dev/null',
                                     '-w', '%{http_code}', url],
                                    capture_output=True, text=True, timeout=10)
            code = result.stdout.strip()
            if code in ['200', '401', '403']:
                print(
                    f"OK Registry {registry_url} available ({protocol.upper()})")
                return True
        except Exception:
            continue

    logging.error(f"Registry {registry_url} not available")
    return False


def generate_registry_tag(image: str, registry_url: str, prefix: str = "",
                          service_name: str = "", compose_image: str = "") -> str:
    """Generate tag for the registry using service name or compose_image.

    For Gitea: registry_url should be 'gitea.example.com' and prefix should be 'user/project'
    Example: gitea.example.com/myuser/myproject/image:tag
    """
    # Extract tag from current image
    if ':' in image and not image.startswith('sha256:'):
        _, tag = image.rsplit(':', 1)
    else:
        tag = 'latest'

    # If tag is a SHA256 hash, use 'latest'
    if tag.startswith('sha256:') or len(tag) == 64:
        tag = 'latest'

    # Determine name to use in registry
    if compose_image:
        # Use compose_image as-is if available (e.g., ucographrag/celery-exporter)
        if ':' in compose_image:
            registry_name = compose_image.split(':')[0]
        else:
            registry_name = compose_image
    elif service_name:
        # Normalize service name (- to _) for Docker compatibility
        registry_name = service_name.replace('-', '_')
    else:
        # Fallback: sanitize current image name
        if ':' in image and not image.startswith('sha256:'):
            name = image.split(':')[0]
        else:
            name = image.replace('sha256:', '')[:12]
        registry_name = name.replace('/', '_').replace('.', '_')

    # Gitea specific: clean names to avoid issues
    registry_name = registry_name.lower().replace('_', '-')

    # Build full tag
    if prefix:
        registry_tag = f"{registry_url}/{prefix}/{registry_name}:{tag}"
    else:
        registry_tag = f"{registry_url}/{registry_name}:{tag}"

    return registry_tag


def get_image_digest(registry_tag: str) -> Optional[str]:
    """Return the digest of the image manifest."""

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
    """Check if image exists in registry by inspecting manifest without downloading."""
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
    """Tag and push image to registry."""
    try:
        # Tag image
        subprocess.run(['docker', 'tag', image, registry_tag],
                       check=True, capture_output=True)

        # Push image with spinner
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

        # Verify image is actually in registry
        verified = verify_image_in_registry(registry_tag)
        if not verified:
            logging.warning(
                f"Could not verify {registry_tag} in registry")

        # Clean up registry tag after push
        try:
            subprocess.run(['docker', 'rmi', registry_tag],
                           capture_output=True, check=False)
        except Exception:
            pass

        return True
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.lower() if e.stderr else ""
        if 'unauthorized' in stderr or '401' in stderr:
            logging.error(f"Authentication error pushing {image}")
            logging.error("Verify credentials with: docker login")
        elif 'denied' in stderr or '403' in stderr:
            logging.error(f"Permission denied for {image}")
        elif 'not found' in stderr or 'unknown' in stderr:
            logging.error(f"Push error: {e.stderr if e.stderr else e}")
            logging.error(f"Registry rejected image {registry_tag}")
            logging.error("Possible causes:")
            logging.error(
                "  1. Missing namespace/project: use --registry-prefix <namespace>")
            logging.error("  2. Project does not exist in registry")
            logging.error("  3. You don't have push permissions in that namespace")
        else:
            logging.error(f"Push error: {e.stderr if e.stderr else e}")
        return False
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout pushing {registry_tag}")
        return False


def pull_image_from_registry(registry_tag: str, original_name: str,
                             timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Pull image from registry and re-tag to original name."""
    try:
        # Pull image with spinner
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

        # Re-tag to original name
        subprocess.run(['docker', 'tag', registry_tag, original_name],
                       check=True, capture_output=True)

        # Optional cleanup of registry tag
        try:
            subprocess.run(['docker', 'rmi', registry_tag],
                           capture_output=True)
        except Exception:
            pass

        return True
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.lower() if e.stderr else ""
        if 'manifest unknown' in stderr or 'not found' in stderr:
            logging.error(f"Image not found: {registry_tag}")
        elif 'unauthorized' in stderr or '401' in stderr:
            logging.error(f"Authentication error: {registry_tag}")
        elif 'denied' in stderr or '403' in stderr:
            logging.error(f"Permission denied: {registry_tag}")
        else:
            logging.error(
                f"Pull error {registry_tag}: {e.stderr if e.stderr else str(e)}")
        return False
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout pulling {registry_tag}")
        return False


# ============================================================================
# Push/pull orchestrators
# ============================================================================

def push_images(images: List[Dict], registry_url: str, prefix: str,
                skip_unchanged: bool, metadata_path: pathlib.Path,
                only_built: bool, timeout: int = DEFAULT_TIMEOUT) -> Dict:
    """Push images to registry with skip logic and metadata tracking."""

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
                print(f"{progress} SKIP {image} (no changes)")
                stats['skipped'] += 1
                continue

        # Push
        if push_image_to_registry(image, registry_tag, timeout):
            print(f"{progress} OK {image}")
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
            print(f"{progress} FAIL {image} (error)")
            # Save failure state in metadata if push failed
            metadata[image] = {
                'push_status': 'failed',
                'failed_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                'id': image_id
            }
            metadata_changed = True
            stats['failed'] += 1

    if metadata_changed:
        save_metadata(metadata_path, metadata)

    return stats


def pull_images(metadata_path: pathlib.Path, timeout: int = DEFAULT_TIMEOUT) -> Dict:
    """Pull images from registry using metadata."""
    metadata = load_metadata(metadata_path) or {}
    
    if not metadata:
        print(f"FAIL No metadata in {metadata_path}")
        return {'pulled': 0, 'skipped': 0, 'failed': 0}

    stats = {'pulled': 0, 'skipped': 0, 'failed': 0}
    items = list(metadata.items())

    print(f"\nPKG Downloading {len(items)} images from registry...\n")
    for idx, (image, info) in enumerate(items, 1):
        progress = f"[{idx}/{len(items)}]"
        
        # Validate that info is dict with registry_tag
        if not isinstance(info, dict):
            print(f"{progress} SKIP {image} (corrupted metadata)")
            stats['skipped'] += 1
            continue
            
        registry_tag = info.get('registry_tag')
        if not registry_tag:
            print(f"{progress} SKIP {image} (missing registry_tag)")
            stats['skipped'] += 1
            continue

        if pull_image_from_registry(registry_tag, image, timeout):
            print(f"{progress} OK {image}")
            stats['pulled'] += 1
        else:
            print(f"{progress} FAIL {image} (error)")
            stats['failed'] += 1

    return stats


def save_images(images: List[Dict], output_dir: pathlib.Path,
                skip_unchanged: bool, metadata_path: pathlib.Path,
                only_built: bool) -> Dict:
    """Save images to .tar files in the specified directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nDIR Output directory: {output_dir}\n")

    metadata = load_metadata(metadata_path)
    metadata_changed = False
    stats = {'saved': 0, 'skipped': 0, 'failed': 0, 'not_found': 0}

    for idx, info in enumerate(images, 1):
        image = info['name']
        progress = f"[{idx}/{len(images)}]"

        if only_built and not info.get('built'):
            print(f"{progress} SKIP {image} (only built)")
            stats['skipped'] += 1
            continue
        if not image_exists(image):
            print(f"{progress} FAIL {image} (not exists)")
            stats['not_found'] += 1
            continue
        if not check_disk_space(output_dir, DISK_CHECK_MB):
            print(f"{progress} FAIL {image} (no space)")
            stats['failed'] += 1
            break

        filename = generate_safe_filename(image, info.get('service'))
        file_path = output_dir / filename
        image_id = get_image_id(image)
        if skip_unchanged and image_id:
            previous = metadata.get(image)
            if previous and previous.get('id') == image_id and file_path.exists():
                print(f"{progress} SKIP {image} (no changes)")
                stats['skipped'] += 1
                continue

        # If image has desired name different from current (compose_image),
        # tag it before saving to ensure docker save preserves correct name
        compose_image = info.get('compose_image', '')
        if compose_image and compose_image != image and image.startswith('sha256:'):
            try:
                subprocess.run(['docker', 'tag', image, compose_image],
                               check=True, capture_output=True)
                save_image = compose_image
            except subprocess.CalledProcessError:
                save_image = image
        else:
            save_image = image

        spinner = Spinner(f"Saving {save_image}")
        spinner.start()
        try:
            subprocess.run(
                ['docker', 'save', '-o', str(file_path), save_image], check=True, timeout=DOCKER_SAVE_TIMEOUT)
            spinner.stop()
            print(f"{progress} OK {save_image}")
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
            print(f"{progress} FAIL {image} (error)")
            logging.error(f"Error saving {image}: {e}")
            stats['failed'] += 1
        except subprocess.TimeoutExpired:
            spinner.stop()
            print(f"{progress} FAIL {image} (timeout)")
            stats['failed'] += 1

    if metadata_changed:
        save_metadata(metadata_path, metadata)

    return stats


def load_images(input_dir: pathlib.Path) -> Dict:
    """Load all .tar images from the specified directory."""
    if not input_dir.exists():
        raise RuntimeError(f"Input directory does not exist: {input_dir}")

    files = list(input_dir.glob('*.tar'))
    stats = {'loaded': 0, 'failed': 0}

    print(f"\nLOAD Loading {len(files)} images...\n")
    for idx, file_path in enumerate(files, 1):
        progress = f"[{idx}/{len(files)}]"
        spinner = Spinner(f"Loading {file_path.name}")
        spinner.start()
        try:
            subprocess.run(
                ['docker', 'load', '-i', str(file_path)], check=True, timeout=DOCKER_SAVE_TIMEOUT)
            spinner.stop()
            print(f"{progress} OK {file_path.name}")
            stats['loaded'] += 1
        except subprocess.CalledProcessError as e:
            spinner.stop()
            print(f"{progress} FAIL {file_path.name} (error)")
            logging.error(f"Error: {e}")
            stats['failed'] += 1
        except subprocess.TimeoutExpired:
            spinner.stop()
            print(f"{progress} FAIL {file_path.name} (timeout)")
            stats['failed'] += 1

    return stats


def get_metadata_path(metadata_file: Optional[str], output_dir: Optional[str]) -> pathlib.Path:
    """Determine the path to the metadata file.
    
    Priority:
    1. --metadata-file if specified
    2. output-dir/image_metadata.json if output-dir specified
    3. ./image_metadata.json in current directory
    """

    if metadata_file:
        return pathlib.Path(metadata_file)
    elif output_dir:
        return pathlib.Path(output_dir) / 'image_metadata.json'
    else:
        return pathlib.Path.cwd() / 'image_metadata.json'


def main():
    parser = argparse.ArgumentParser(
        description="Save/load Docker images to disk or push/pull from registry")

    parser.add_argument(
        '--action', choices=['save', 'load', 'push', 'pull'], required=True,
        help="Action: save/load (disk) or push/pull (registry)")
    parser.add_argument('--docker-compose', dest='docker_compose',
                        help="Path to docker-compose.yml file (required for save/push)")
    parser.add_argument('--output-dir',
                        help="Directory to save/load images (disk mode only)")

    # Common options
    parser.add_argument('--skip-unchanged', action='store_true',
                        help="Do not re-save/push unchanged images")
    parser.add_argument('--only-built', action='store_true',
                        help="Only locally built images (services with build)")
    parser.add_argument('--exclude-registry', action='append', dest='exclude_registries',
                        help="Exclude images from this registry when using save without docker-compose (can repeat)")
    parser.add_argument('--metadata-file', dest='metadata_file',
                        help="Path to JSON file with metadata. Default: output-dir/image_metadata.json")
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f"Timeout in seconds for operations (default: {DEFAULT_TIMEOUT})")

    # Registry options
    parser.add_argument('--registry-url',
                        help="Registry URL (e.g., localhost:5000)")
    parser.add_argument('--registry-prefix', default='',
                        help="Prefix to organize images in registry (e.g., project)")
    parser.add_argument('--registry-user',
                        help="Username for registry authentication")
    parser.add_argument('--registry-password',
                        help="Password for authentication (prefer environment variables)")
    parser.add_argument('--registry-config',
                        help="JSON file with registry configuration")
    parser.add_argument('--skip-login', action='store_true',
                        help="Do not attempt login (assume already authenticated)")
    parser.add_argument('--auto-logout', action='store_true',
                        help="Logout from registry when done")
    parser.add_argument('--generate-compose',
                        help="Generate new docker-compose.yml with registry images (push only)")

    args = parser.parse_args()

    if not check_docker_available():
        sys.exit(1)

    # Determine mode: disk or registry
    is_registry_mode = args.action in ['push', 'pull']

    # Load config if exists (before validations)
    registry_config_path = pathlib.Path(
        args.registry_config) if args.registry_config else None
    loaded_config = {}
    if registry_config_path:
        try:
            loaded_config = load_registry_config(registry_config_path)
        except Exception as e:
            logging.warning(f"Could not load registry_config: {e}")

    # Validations
    if is_registry_mode:
        registry_url_from_config = loaded_config.get('registry_url')
        if not args.registry_url and not registry_url_from_config:
            logging.error(
                "--registry-url is required for push/pull (or specify in registry_config)")
            sys.exit(1)
        if not args.docker_compose:
            logging.error("--docker-compose is required for push/pull")
            sys.exit(1)
    else:  # disk mode (save/load)
        if not args.output_dir:
            logging.error("--output-dir is required for save/load")
            sys.exit(1)
        if not args.docker_compose:
            logging.error("--docker-compose is required for save/load")
            sys.exit(1)

    # Metadata path
    metadata_path = get_metadata_path(args.metadata_file, args.output_dir)

    # Execute action
    if args.action == 'save':
        output_dir = pathlib.Path(args.output_dir)

        if args.docker_compose:
            # Use images from docker-compose
            docker_compose_path = pathlib.Path(args.docker_compose)
            images, _ = parse_docker_compose(docker_compose_path)
        else:
            # Use all local images
            print(
                "INFO No docker-compose specified, saving all local images")
            check_docker_available()

            # Detect registries to exclude from config, args or --exclude-registry
            exclude_registries = []
            if loaded_config.get('registry_url'):
                exclude_registries.append(loaded_config.get('registry_url'))
            if args.registry_url:
                exclude_registries.append(args.registry_url)
            if args.exclude_registries:
                exclude_registries.extend(args.exclude_registries)

            # Remove duplicates
            exclude_registries = list(set(exclude_registries))

            if exclude_registries:
                print(
                    f"EXCLUDE Excluding images from: {', '.join(exclude_registries)}")

            images = get_all_local_images(exclude_registries)
            if not images:
                print("FAIL No local images found")
                sys.exit(1)

        stats = save_images(images, output_dir, args.skip_unchanged,
                            metadata_path, args.only_built)

        # Summary
        print("\n" + "=" * 50)
        print("SUMMARY:")
        print(f"   OK Saved:  {stats['saved']}")
        print(f"   SKIP Skipped:   {stats['skipped']}")
        print(f"   FAIL Failed:   {stats['failed']}")
        if stats['not_found'] > 0:
            print(f"   EXCLUDE Not found: {stats['not_found']}")
        print(f"   FILE Metadata: {metadata_path}")
        print("=" * 50)

    elif args.action == 'load':
        output_dir = pathlib.Path(args.output_dir)
        stats = load_images(output_dir)

        # Summary
        print("\n" + "=" * 50)
        print("SUMMARY:")
        print(f"   OK Loaded:   {stats['loaded']}")
        print(f"   FAIL Failed:   {stats['failed']}")
        print("=" * 50)

    elif args.action == 'push':
        if not args.docker_compose:
            print("FAIL Error: --docker-compose is required for 'push' action")
            sys.exit(1)
        # Load config if exists to get registry_url and prefix
        registry_url = args.registry_url or loaded_config.get(
            'registry_url', '')
        registry_prefix = args.registry_prefix or loaded_config.get(
            'prefix', '')

        print("\n" + "=" * 60)
        print("DOCKER Registry Push Tool")
        print("=" * 60)
        print(f"REG Registry: {registry_url}")
        print(f"PKG Prefix: {registry_prefix or '(none)'}")
        print(f"FILE Compose: {args.docker_compose}")
        print("=" * 60 + "\n")

        # Verify registry
        if not check_registry_available(registry_url):
            sys.exit(1)

        # Authentication
        auth_success, config_data = ensure_registry_auth(
            registry_url, args.registry_user,
            args.registry_password, registry_config_path,
            args.skip_login)
        if not auth_success:
            sys.exit(1)

        # Push images
        docker_compose_path = pathlib.Path(args.docker_compose)
        images, compose_data = parse_docker_compose(docker_compose_path)
        print(f"LIST Processing {len(images)} images...\n")
        stats = push_images(images, registry_url, registry_prefix,
                            args.skip_unchanged, metadata_path, args.only_built,
                            args.timeout)

        # Summary
        print("\n" + "=" * 50)
        print("SUMMARY:")
        print(f"   OK Pushed:    {stats['pushed']}")
        print(f"   SKIP Skipped:   {stats['skipped']}")
        print(f"   FAIL Failed:   {stats['failed']}")
        if stats['not_found'] > 0:
            print(f"   EXCLUDE Not found: {stats['not_found']}")
        print(f"   FILE Metadata: {metadata_path}")
        print("=" * 50)

        # Generate new docker-compose if requested
        if args.generate_compose:
            output_compose = pathlib.Path(args.generate_compose)
            print("\nGEN Generating docker-compose for registry...")
            generate_registry_compose(compose_data, images, registry_url,
                                      registry_prefix, output_compose)

        # Logout if requested
        auto_logout = args.auto_logout or config_data.get('auto_logout', False)
        if auto_logout:
            docker_logout(registry_url)

    elif args.action == 'pull':
        registry_url = args.registry_url or loaded_config.get(
            'registry_url', '')

        print("\n" + "=" * 60)
        print("DOCKER Registry Pull Tool")
        print("=" * 60)
        print(f"REG Registry: {registry_url}")
        print(f"FILE Metadata: {metadata_path}")
        print("=" * 60 + "\n")

        # Verify registry
        if not check_registry_available(registry_url):
            sys.exit(1)

        # Authentication
        auth_success, config_data = ensure_registry_auth(
            registry_url, args.registry_user,
            args.registry_password, registry_config_path,
            args.skip_login)
        if not auth_success:
            sys.exit(1)

        # Pull images
        stats = pull_images(metadata_path, args.timeout)

        # Summary
        print("\n" + "=" * 50)
        print("SUMMARY:")
        print(f"   OK Downloaded: {stats['pulled']}")
        print(f"   SKIP Skipped:    {stats['skipped']}")
        print(f"   FAIL Failed:    {stats['failed']}")
        print("=" * 50)

        # Logout if requested
        auto_logout = args.auto_logout or config_data.get('auto_logout', False)
        if auto_logout:
            docker_logout(registry_url)


if __name__ == "__main__":
    main()
