# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial comprehensive documentation
- GitHub-ready project structure

### Changed
- Improved README with real-world examples
- Enhanced code comments for clarity

### Fixed
- Registry detection for port numbers
- File permission handling for metadata

## [1.0.0] - 2025-03-03

### Added

#### Core Features
- **Two operation modes**: Disk (save/load) and Registry (push/pull)
- **Metadata tracking**: JSON with image IDs, digests, timestamps, and push status
- **Smart filtering**: `--only-built` and `--skip-unchanged` options
- **Auto-generate docker-compose**: Creates production-ready compose files for registry images
- **Flexible authentication**: Environment variables, CLI, config file, or existing Docker login
- **Enhanced UX**: Animated spinners and emoji feedback
- **Auto-detection**: HTTPS/HTTP protocol and existing authentication checks
- **Secure credential handling**: chmod 600 permissions for credential files

#### Functions
- `image_has_registry()`: Detect if image name contains registry
- `get_metadata_path()`: Resolve metadata file path with priority system
- `save_metadata()`: Save image metadata with secure permissions
- `load_metadata()`: Load and validate metadata
- `check_disk_space()`: Verify available disk space before operations
- `generate_safe_filename()`: Create safe, readable filenames from image names
- `generate_registry_tag()`: Generate registry-compatible image tags
- `push_images()`: Upload images to Docker registry
- `pull_images()`: Download images from Docker registry
- `save_images()`: Save images to disk as tar archives
- `load_images()`: Load images from tar archives

#### Documentation
- Complete README with quick start guide
- Usage examples for disk and registry modes
- Configuration templates
- Troubleshooting guide
- Real-world use cases (offline, corporate registry, multi-environment)
- CI/CD workflow examples
- Complete API documentation

#### Testing
- 15 comprehensive unit tests
- Test coverage for:
  - Registry detection (`TestImageHasRegistry`)
  - Safe filename generation (`TestGenerateSafeFilename`)
  - Metadata path resolution (`TestGetMetadataPath`)
  - Metadata save/load (`TestMetadata`)
  - Disk space verification (`TestDiskSpace`)
- 100% test pass rate
- Pytest integration

#### Development
- Code style guidelines (PEP 8)
- Development documentation (AGENTS.md)
- Contributing guidelines
- MIT License

### Fixed
- Disk space conversion formula (bytes to MB)
- Registry detection with port numbers in image names
- Metadata validation to prevent corruption
- File permission enforcement for sensitive files
- Logging format strings

### Security
- Implemented chmod 600 for credential files
- Safe metadata validation before processing
- Secure error handling without exposing sensitive data

### Performance
- Skip unchanged images with `--skip-unchanged` option
- Only process built images with `--only-built` option
- Incremental updates based on metadata tracking

---

## Legend

- **Added**: New features
- **Changed**: Changes in existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security fixes and enhancements

## Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR version**: Incompatible API changes
- **MINOR version**: New functionality in backward-compatible manner
- **PATCH version**: Backward-compatible bug fixes

---

**Note**: For detailed commit history, see the [Git Log](https://github.com/yourusername/move-images/commits/main).
