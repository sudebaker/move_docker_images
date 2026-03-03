#!/usr/bin/env python3
"""Tests básicos para move_images.py"""

import pytest
import tempfile
import json
from pathlib import Path
from move_images import (
    image_has_registry,
    generate_safe_filename,
    get_metadata_path,
    load_metadata,
    save_metadata,
    check_disk_space
)


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


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
