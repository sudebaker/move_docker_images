# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, **please do not open a public issue**. Instead:

1. **Email** your findings to: `security@example.com`
2. **Include details** about the vulnerability:
   - Type of vulnerability (e.g., credential exposure, command injection)
   - Affected component or function
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

3. **Allow time for response** - We will acknowledge receipt within 24 hours

We appreciate your responsible disclosure and will:
- Acknowledge receipt of your report
- Assess the severity
- Work on a fix
- Notify you when a patch is available
- Credit you in the security advisory (if you wish)

## Security Best Practices

### Using This Tool Securely

#### 1. Credential Management

**Never commit credentials** to version control:

```bash
# ✅ GOOD: Use environment variables
export REGISTRY_USER=myuser
export REGISTRY_PASSWORD=mypass
python move_images.py push --docker-compose docker-compose.yml --registry-url registry.example.com

# ✅ GOOD: Use configuration file with restricted permissions
chmod 600 registry_config.json
python move_images.py push --docker-compose docker-compose.yml --registry-config registry_config.json

# ❌ BAD: Hardcoding credentials in CLI
python move_images.py push ... --registry-password "mypassword"

# ❌ BAD: Committing registry_config.json
git add registry_config.json  # NEVER do this!
```

#### 2. File Permissions

The tool automatically sets `chmod 600` on metadata files, but verify:

```bash
# Check metadata file permissions (should show: -rw-------)
ls -l image_metadata.json

# Check registry config permissions
ls -l registry_config.json
```

#### 3. Docker Authentication

The tool uses Docker's standard authentication mechanisms:

```bash
# Automatic checks (in order):
# 1. ~/.docker/config.json (existing login)
# 2. REGISTRY_USER and REGISTRY_PASSWORD env vars
# 3. registry_config.json file
# 4. CLI arguments --registry-user and --registry-password
# 5. Interactive prompt
```

**Best practice**: Use environment variables or config file, never CLI args.

#### 4. Registry Security

Use HTTPS for registry URLs:

```bash
# ✅ GOOD: HTTPS
--registry-url registry.example.com

# ⚠️ Only for local/testing: HTTP
--registry-url localhost:5000
```

#### 5. CI/CD Pipeline Security

For secure CI/CD integration:

```bash
#!/bin/bash
# Deploy script - secure practices

# Set strict error handling
set -euo pipefail

# Use secrets management (not shown in logs)
export REGISTRY_USER="${CI_REGISTRY_USER}"
export REGISTRY_PASSWORD="${CI_REGISTRY_PASSWORD}"

# Push images (credentials never logged)
python move_images.py push \
  --docker-compose docker-compose.yml \
  --registry-url "${REGISTRY_URL}" \
  --registry-prefix "${REGISTRY_PREFIX}" \
  --skip-login

# Clear sensitive variables
unset REGISTRY_USER
unset REGISTRY_PASSWORD
```

### For Project Maintainers

#### Security Review Process

1. **Review dependencies** regularly
   ```bash
   pip check
   pip install --upgrade pyyaml
   ```

2. **Review code** for:
   - Credential exposure in logs
   - Unsafe subprocess calls
   - Unvalidated user input
   - Insecure file operations

3. **Test** security scenarios:
   - Invalid credentials
   - Unreachable registries
   - Corrupted metadata
   - File permission issues

4. **Update dependencies** when security patches are available

#### Known Vulnerabilities

Currently, there are **no known security vulnerabilities** in this project.

The project uses minimal dependencies:
- `pyyaml` - YAML parser (well-maintained, security patches available)
- Python standard library for subprocess, file, and network operations

## Security Considerations

### What This Tool Does NOT Do

- ❌ Scan images for vulnerabilities
- ❌ Encrypt data in transit (uses Docker's native HTTPS)
- ❌ Store credentials permanently (uses Docker's standard mechanisms)
- ❌ Validate image signatures (uses Docker Registry V2 API)

### What This Tool DOES Do

- ✅ Enforce file permissions (chmod 600) on credential files
- ✅ Use secure subprocess calls (no shell execution)
- ✅ Validate input before subprocess operations
- ✅ Use Docker's native authentication (no custom credential handling)
- ✅ Support environment variables (recommended over CLI args)

### Attack Surface

1. **Metadata file** - Contains non-sensitive image metadata and push history
2. **Docker socket** - Uses standard Docker API (same as `docker` CLI)
3. **Registry communication** - Uses HTTPS and Docker authentication
4. **Configuration file** - May contain credentials (use chmod 600)

## Dependencies Security

### Current Dependencies

- **pyyaml** (5.1+) - YAML parsing
  - Well-maintained and actively patched
  - No security vulnerabilities in recent versions
  - Pinned to version 5.1+ (supports Python 3.7+)

### Future Dependency Updates

The project aims to keep dependencies minimal and secure:

1. Only add dependencies with clear justification
2. Prefer standard library over external packages
3. Monitor security advisories via GitHub's dependabot
4. Update regularly for security patches

## Compliance

This tool is designed for enterprise use and follows security best practices:

- ✅ No hardcoded credentials
- ✅ No credentials in default files
- ✅ Uses standard Docker security mechanisms
- ✅ File permission enforcement
- ✅ Minimal attack surface
- ✅ Clear audit trail (metadata tracking)

## Security Resources

### Learning Resources

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [OWASP: Secrets Management](https://owasp.org/www-community/attacks/Sensitive_Data_Exposure)
- [Python Security Best Practices](https://python.readthedocs.io/en/latest/library/security_warnings.html)

### Tools for Security

```bash
# Check for hardcoded credentials
grep -r "password\|secret\|token" . --exclude-dir=.git

# Check file permissions
find . -type f -name "*.json" -exec ls -l {} \;

# Verify Python syntax
python -m py_compile move_images.py

# Run security checks (if bandit is installed)
pip install bandit
bandit -r move_images.py
```

## Acknowledgments

Thank you for helping us maintain the security of this project. We appreciate responsible disclosure and the security research community.

---

**Last Updated**: 2025-03-03
**Maintainer**: [Your Name/Organization]
