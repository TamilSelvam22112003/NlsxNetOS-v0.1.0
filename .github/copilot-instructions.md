# NlsxNetOS - GitHub Copilot Instructions

## Project

NlsxNetOS is an Ubuntu/Debian-based networking operating system toolkit.

The project is primarily written in Python and shell scripts.

The goal is to develop NlsxNetOS into a reliable networking operating system
platform capable of network configuration, routing, security tooling,
automation, diagnostics, and NLS integration.

## Repository Structure

- `nls/` - main Python package
- `cmd/nls/` - command-line entrypoint
- `config/` - configuration files
- `docs/` - project documentation
- `examples/` - examples and demonstrations
- `scripts/` - installation, build, testing and administration scripts
- `systemd/` - systemd service definitions
- `tests/` - automated tests
- `packaging/deb/DEBIAN/` - Debian packaging
- `pyproject.toml` - Python project configuration
- `requirements.txt` - Python dependencies
- `Makefile` - development/build commands
- `install.sh` - installation script

## Important Rules

1. Do not rename existing directories or files unless explicitly required.
2. Do not remove existing functionality without explaining why.
3. Preserve backward compatibility whenever possible.
4. Do not invent files or modules that do not exist.
5. Inspect the repository before modifying architecture.
6. Prefer small, testable changes.
7. Update documentation when functionality changes.
8. Add tests for new functionality.
9. Never commit secrets, API keys, passwords, private keys or credentials.
10. Never disable security controls merely to make tests pass.

## Python

Use the Python version defined by `pyproject.toml`.

Use type hints where practical.

Follow PEP 8.

Prefer standard-library functionality where practical.

Avoid unnecessary dependencies.

## Shell

Shell scripts must:

- use Bash
- use `set -Eeuo pipefail` where appropriate
- check command failures
- provide useful error messages
- avoid destructive commands unless explicitly required
- be safe to execute repeatedly where possible
- detect Ubuntu/Debian versions before installing packages

## Networking

NlsxNetOS is a networking project.

Changes involving networking must consider:

- IPv4
- IPv6
- routing
- DNS
- DHCP
- firewalling
- Linux kernel networking
- network interfaces
- systemd services
- routing daemons

Do not change network configuration blindly.

## Testing

Before considering a change complete:

1. Run syntax checks.
2. Run unit tests.
3. Run integration tests where applicable.
4. Run shellcheck on shell scripts.
5. Validate configuration files.
6. Build/package the project when relevant.

Use the repository's existing test and build commands whenever available.

## Installation

The installation process must work on supported Ubuntu/Debian systems.

Do not assume that a clean GitHub Actions runner has the same state as a user's physical machine.

Detect:

- OS version
- architecture
- installed packages
- Python version
- Docker availability
- FRRouting availability
- systemd availability

before performing system-level operations.

## CI/CD

GitHub Actions must:

1. Install dependencies.
2. Run static checks.
3. Run Python tests.
4. Run shell checks.
5. Validate packaging.
6. Build artifacts.
7. Run security checks.
8. Upload useful artifacts.

CI failures must be investigated rather than bypassed.

## Security

Security is a primary requirement.

Never:

- hardcode credentials
- commit private keys
- disable TLS verification without justification
- weaken authentication
- silently ignore security warnings
- execute untrusted downloaded scripts without verification

For cryptographic functionality, use established libraries and algorithms.

## Documentation

When adding a major feature, update:

- README.md
- relevant documentation under `docs/`
- CHANGELOG.md where appropriate

Document installation, usage, configuration and troubleshooting.

## Git Workflow

Prefer:

feature branch -> changes -> tests -> pull request -> review -> merge

Do not directly rewrite history.

Do not force push unless explicitly requested.

Commit messages should clearly describe the change.

## Copilot Behavior

Before making substantial changes:

1. Inspect the repository.
2. Understand the current architecture.
3. Identify dependencies.
4. Check existing tests.
5. Implement the smallest coherent change.
6. Test it.
7. Report what changed and what remains.

Never claim that something works unless it has actually been tested.



Work on the NlsxNetOS repository.

First inspect the complete repository structure.

Do not assume files, modules or directories exist.

Understand the existing architecture, pyproject.toml,
Makefile, install.sh, tests, systemd files and documentation.

Then:

1. Audit the current project.
2. Identify missing components required for a production-quality
   Ubuntu/Debian networking OS toolkit.
3. Create a robust scripts/NlsxNetOS-Setup.sh installer.
4. Make it support Ubuntu 22.04 and Ubuntu 24.04.
5. Detect the operating system and CPU architecture.
6. Check and repair package-manager state safely.
7. Install required system dependencies.
8. Configure Python according to pyproject.toml.
9. Configure networking dependencies.
10. Detect and configure FRRouting where required.
11. Configure Docker only if the repository actually requires Docker.
12. Configure IPv4/IPv6 forwarding only where appropriate.
13. Create a Python virtual environment.
14. Install the project.
15. Run the project's tests.
16. Run shellcheck on shell scripts.
17. Validate systemd files.
18. Validate packaging.
19. Create a useful installation log.
20. Make the script safe to execute repeatedly.
21. Update documentation.
22. Add tests for new functionality where appropriate.
23. Update CHANGELOG.md.

Do not delete existing functionality.

Do not replace install.sh unless there is a documented reason.

When complete, create a pull request containing all changes.

In the pull request description explain:
- files changed
- architecture changes
- installation procedure
- tests performed
- test results
- known limitations
- security considerations


Audit this repository completely.

Inspect every source directory, Python package,
shell script, systemd unit, configuration file,
test and packaging file.

Create docs/PROJECT-AUDIT.md.

Do not modify application functionality yet.



Improve the NlsxNetOS build system.

Inspect pyproject.toml and Makefile.

Ensure the project can:

- install
- uninstall
- run
- test
- lint
- package

Add missing targets where necessary.

Do not invent unnecessary dependencies.

Run all tests after modification.

Implement a production-quality Ubuntu/Debian installer.

Create:

scripts/NlsxNetOS-Setup.sh

Requirements:

- Ubuntu 22.04
- Ubuntu 24.04
- architecture detection
- dependency detection
- dpkg/apt health checks
- Python environment
- networking tools
- FRRouting detection/configuration
- systemd integration
- logging
- rollback/error handling
- idempotent execution
- dry-run option
- uninstall option where safe

Test it in a clean Ubuntu VM.

Do not assume packages exist without checking.



Build a complete GitHub Actions CI/CD pipeline for NlsxNetOS.

First inspect the actual repository.

Create workflows under:

.github/workflows/

The pipeline should perform:

- Python syntax validation
- unit tests
- integration tests
- shellcheck
- YAML validation
- systemd validation
- security scanning
- dependency auditing
- Debian package validation
- build validation

Use supported Ubuntu GitHub Actions runners.

Do not add Docker unless the repository actually requires Docker.

Do not make CI pass by suppressing failures.

Upload useful build/test artifacts.


Fix the security vulnerabilities identified in
docs/SECURITY-AUDIT.md.

For every fix:

- explain the vulnerability
- implement the fix
- add a regression test
- run the complete test suite

You are the NlsxNetOS networking specialist.

Focus on:

- Linux networking
- IPv4
- IPv6
- routing
- FRRouting
- OSPF
- DHCP
- DNS
- interfaces
- firewalling
- network namespaces

Never modify networking configuration without
checking the existing architecture.

Always provide validation commands.


You are the NlsxNetOS security specialist.

Focus on:

- secure coding
- privilege boundaries
- cryptography
- authentication
- authorization
- dependency security
- systemd security
- Linux permissions
- supply-chain security

Never introduce hardcoded credentials.

Prefer established cryptographic libraries.


Develop NlsxNetOS into a complete Ubuntu/Debian-based
network operating system platform.

Work incrementally.

First audit the existing implementation.

Then implement and validate:

1. Core operating environment
2. Network management
3. IPv4 support
4. IPv6 support
5. Routing
6. FRRouting integration
7. DNS management
8. DHCP management
9. Firewall management
10. Network diagnostics
11. CLI
12. Configuration management
13. systemd integration
14. Security hardening
15. NLS integration
16. Python API
17. REST/API layer where appropriate
18. Monitoring
19. Logging
20. Packaging
21. Installer
22. Upgrade mechanism
23. Uninstaller
24. Automated testing
25. Security testing
26. CI/CD
27. Debian package
28. ISO/live-image build
29. Documentation

For every phase:

- inspect existing code
- make incremental changes
- write tests
- run tests
- update documentation
- update CHANGELOG
- create a pull request

Never skip testing.
Never silently delete existing functionality.
Never claim successful implementation without verification.





