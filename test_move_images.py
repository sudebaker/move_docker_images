#!/usr/bin/env python3
"""Tests básicos para move_images.py"""

import pytest
import subprocess
import tempfile
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import move_images as mi
from move_images import (
    image_has_registry,
    generate_safe_filename,
    get_metadata_path,
    load_metadata,
    save_metadata,
    check_disk_space,
    push_image_to_registry,
    parse_docker_compose,
    generate_registry_tag,
    find_compose_command
)


@pytest.fixture(autouse=True)
def _reset_compose_cache():
    """Aísla el caché global del comando compose entre tests."""
    old = mi._COMPOSE_CMD
    mi._COMPOSE_CMD = None
    yield
    mi._COMPOSE_CMD = old


class TestImageHasRegistry:
    """Tests para la detección de registries en nombres de imágenes."""
    
    def test_registry_with_domain(self):
        """Imagen con dominio."""
        assert image_has_registry('git.ucosistemas.gc/sistemas/image:tag')
        assert image_has_registry('quay.io/myorg/image:latest')
        assert image_has_registry('docker.io/library/ubuntu:20.04')
    
    def test_registry_with_port(self):
        """Imagen con puerto - nota: localhost:5000 es ambiguo sin /."""
        # Este es un caso edge: localhost:5000 sin / se interpreta como repo:tag
        # La función es correcta al no detectorlo. En práctica, Docker usa:
        # - localhost:5000/image:tag (con /)
        assert image_has_registry('myregistry:5000/image:latest')
    
    def test_no_registry(self):
        """Imagen sin registry."""
        assert not image_has_registry('ubuntu:20.04')
        assert not image_has_registry('myimage:latest')
        assert not image_has_registry('myorg/myimage:tag')


class TestGenerateSafeFilename:
    """Tests para generación de nombres seguros."""
    
    def test_with_service_name(self):
        """Con nombre de servicio."""
        filename = generate_safe_filename('myimage:latest', 'my-service')
        # La función NO reemplaza guiones, solo slash y colon
        assert filename == 'my-service_latest.tar'
    
    def test_without_tag(self):
        """Sin tag."""
        filename = generate_safe_filename('ubuntu', 'my-service')
        assert filename == 'my-service_latest.tar'
    
    def test_sha256_hash(self):
        """Con hash SHA256."""
        filename = generate_safe_filename('sha256:abc123def456', None)
        assert filename.startswith('image_abc123')
        assert filename.endswith('.tar')
    
    def test_normal_image(self):
        """Imagen normal sin servicio."""
        filename = generate_safe_filename('ubuntu:20.04', None)
        assert filename == 'ubuntu_20.04.tar'

    def test_registry_port_without_tag(self):
        """Imagen con puerto y sin tag: el nombre no debe contener '/'."""
        filename = generate_safe_filename('localhost:5000/app', 'my-svc')
        assert filename == 'my-svc_latest.tar'


class TestGetMetadataPath:
    """Tests para resolución de ruta metadata."""
    
    def test_explicit_metadata_file(self):
        """Con --metadata-file especificado."""
        path = get_metadata_path('/custom/metadata.json', '/output')
        assert str(path) == '/custom/metadata.json'
    
    def test_with_output_dir(self):
        """Con --output-dir."""
        path = get_metadata_path(None, '/output')
        assert str(path) == '/output/image_metadata.json'
    
    def test_default(self):
        """Sin argumentos."""
        path = get_metadata_path(None, None)
        assert path.name == 'image_metadata.json'


class TestMetadata:
    """Tests para funciones de metadata."""
    
    def test_load_nonexistent(self):
        """Cargar metadata no existente."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / 'nonexistent.json'
            result = load_metadata(path)
            assert result == {}
    
    def test_save_and_load(self):
        """Guardar y cargar metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / 'metadata.json'
            data = {
                'image1': {'id': 'sha256:abc', 'pushed_at': '2025-03-03T00:00:00'},
                'image2': {'id': 'sha256:def', 'failed': True}
            }
            
            save_metadata(path, data)
            loaded = load_metadata(path)
            
            assert loaded == data
            assert path.exists()
            assert path.stat().st_mode & 0o077 == 0  # Permisos 600
    
    def test_load_corrupted(self):
        """Cargar metadata corrupta."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / 'corrupted.json'
            path.write_text('invalid json {]')
            
            result = load_metadata(path)
            assert result == {}  # Devuelve dict vacío en error


class TestDiskSpace:
    """Tests para verificación de espacio en disco."""
    
    def test_check_disk_space_success(self):
        """Hay espacio suficiente."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Verificar con un requerimiento bajo (1 MB debería ser suficiente en /tmp)
            result = check_disk_space(Path(tmpdir), required_mb=1)
            assert result is True
    
    def test_check_disk_space_failure(self):
        """No hay espacio suficiente."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Pedir 10TB debería fallar
            result = check_disk_space(Path(tmpdir), required_mb=10_000_000)
            assert result is False


class TestPushImageOrder:
    """Regresión: docker tag debe ejecutarse ANTES que docker push.

    El registry_tag generado no existe localmente hasta ejecutar docker tag;
    hacer push antes del tag falla siempre.
    """

    def _fake_run(self, calls):
        def fake_run(cmd, **kwargs):
            calls.append(cmd[1])
            mock = MagicMock()
            mock.returncode = 0
            mock.stdout = ''
            mock.stderr = ''
            return mock
        return fake_run

    def test_tag_before_push(self):
        """El push solo se ejecuta después de tagear la imagen."""
        calls = []
        with patch('subprocess.run', side_effect=self._fake_run(calls)):
            result = push_image_to_registry(
                'myimage:latest',
                'registry.example.com/prefix/myimage:latest')

        assert result is True
        assert 'tag' in calls and 'push' in calls
        assert calls.index('tag') < calls.index('push')

    def test_tag_failure_aborts(self):
        """Si falla el tag, no se intenta el push."""
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd[1])
            if cmd[1] == 'tag':
                raise subprocess.CalledProcessError(1, cmd)
            mock = MagicMock()
            mock.returncode = 0
            return mock

        with patch('subprocess.run', side_effect=fake_run):
            result = push_image_to_registry('myimage:latest', 'reg/x:latest')

        assert result is False
        assert 'push' not in calls


class TestGenerateRegistryTag:
    """Tests para generación de tags de registry."""

    def test_basic_with_service(self):
        """Tag con servicio y prefijo."""
        tag = generate_registry_tag('myimage:latest', 'reg.example.com', 'ns',
                                    service_name='my-svc')
        assert tag == 'reg.example.com/ns/my-svc:latest'

    def test_extract_tag_from_version(self):
        """Extrae el tag de versión real."""
        tag = generate_registry_tag('ubuntu:20.04', 'reg.example.com', 'ns',
                                    service_name='my-svc')
        assert tag == 'reg.example.com/ns/my-svc:20.04'

    def test_registry_port_without_tag(self):
        """El puerto del registry no debe interpretarse como tag."""
        tag = generate_registry_tag('localhost:5000/app', 'reg.example.com',
                                    'ns', service_name='app-svc')
        assert tag == 'reg.example.com/ns/app-svc:latest'
        assert '/' not in tag.rsplit(':', 1)[-1]

    def test_sha256_uses_latest(self):
        """Imagen por hash sha256: usa tag latest."""
        tag = generate_registry_tag('sha256:abc123', 'reg.example.com', 'ns',
                                    service_name='my-svc')
        assert tag == 'reg.example.com/ns/my-svc:latest'

    def test_compose_image_preferred(self):
        """compose_image se usa como nombre en el registry (estilo Gitea)."""
        tag = generate_registry_tag('sha256:abc123', 'reg.example.com', 'ns',
                                    service_name='svc',
                                    compose_image='myorg/celery-exporter')
        assert tag == 'reg.example.com/ns/myorg/celery-exporter:latest'


class TestParseDockerCompose:
    """Tests para parseo de docker-compose.yml."""

    def test_empty_yaml_raises(self, tmp_path):
        """YAML vacío no debe causar AttributeError."""
        compose = tmp_path / 'docker-compose.yml'
        compose.write_text('')
        with pytest.raises(RuntimeError) as excinfo:
            parse_docker_compose(compose)
        assert 'vacío' in str(excinfo.value)

    def test_parse_services(self, tmp_path):
        """Extrae imágenes y servicios del compose (salida JSON simulada)."""
        compose = tmp_path / 'docker-compose.yml'
        compose.write_text(
            'services:\n'
            '  web:\n'
            '    image: myorg/web:1.0\n'
        )

        def fake_run(cmd, **kwargs):
            mock = MagicMock()
            mock.returncode = 0
            if 'images' in cmd:
                mock.stdout = json.dumps([
                    {'Repository': 'myorg', 'Tag': '1.0', 'Service': 'web'}])
            return mock

        with patch('subprocess.run', side_effect=fake_run):
            images, data = parse_docker_compose(compose)

        assert images[0]['name'] == 'myorg:1.0'
        assert images[0]['service'] == 'web'
        assert images[0]['compose_image'] == 'myorg/web:1.0'
        assert images[0]['built'] is False


class TestFindComposeCommand:
    """Detección del comando compose (plugin v2 preferido sobre binario v1)."""

    def test_prefers_v2_plugin(self):
        def fake_run(cmd, **kwargs):
            if cmd[:2] == ['docker-compose']:
                raise subprocess.CalledProcessError(1, cmd)
            mock = MagicMock()
            mock.returncode = 0
            return mock

        with patch('subprocess.run', side_effect=fake_run):
            assert find_compose_command() == ['docker', 'compose']

    def test_falls_back_to_v1(self):
        def fake_run(cmd, **kwargs):
            if cmd[:2] == ['docker', 'compose']:
                raise subprocess.CalledProcessError(1, cmd)
            mock = MagicMock()
            mock.returncode = 0
            return mock

        with patch('subprocess.run', side_effect=fake_run):
            assert find_compose_command() == ['docker-compose']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
