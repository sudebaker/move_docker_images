# 🚀 Quick Start Guide

## Installation

```bash
git clone https://github.com/yourusername/move-images.git
cd move-images
pip install -r requirements.txt
```

## 30-Second Overview

### Save Images to Disk
```bash
python move_images.py save --docker-compose docker-compose.yml --output-dir ./images
```

### Load Images from Disk
```bash
python move_images.py load --output-dir ./images
```

### Push to Registry
```bash
python move_images.py push --docker-compose docker-compose.yml --registry-url registry.com
```

### Pull from Registry
```bash
python move_images.py pull --registry-config registry_config.json
```

## Common Use Cases

### Only Push Built Images
```bash
python move_images.py push --docker-compose docker-compose.yml --registry-url registry.com --only-built
```

### Skip Unchanged Images (Faster)
```bash
python move_images.py push --docker-compose docker-compose.yml --registry-url registry.com --skip-unchanged
```

### Generate Production Compose
```bash
python move_images.py push --docker-compose docker-compose.yml --registry-url registry.com --generate-compose docker-compose.prod.yml
```

## Using Environment Variables for Auth
```bash
export REGISTRY_USER=myuser
export REGISTRY_PASSWORD=mypass
python move_images.py push --docker-compose docker-compose.yml --registry-url registry.com
```

## View All Options
```bash
python move_images.py --help
```

## Run Tests
```bash
python -m pytest test_move_images.py -v
```

## Development

```bash
# Install dev dependencies
make install-dev

# Run tests
make test

# Check syntax
make lint

# View all commands
make help
```

## Useful Links

- **Full README**: [README.md](README.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security**: [SECURITY.md](SECURITY.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

For detailed documentation, see [README.md](README.md)
