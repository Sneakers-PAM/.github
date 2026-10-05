# Sneakers-PAM 👟

> 🔐 Open-source privileged access management, built as a set of small services.

Sneakers-PAM is an open-source, Apache-2.0 licensed privileged access management
system: a vault for credentials, scoped secret delivery to the systems that need them,
and an audit trail for every access, built as a set of small services rather than one
monolith.

🌍 **Project site:** [sneakers-pam.com](https://sneakers-pam.com)

## 🧩 Services

- [sneakers-vault](https://github.com/Sneakers-PAM/sneakers-vault): secrets, versions, rotation, heartbeats, approvals, check-out and check-in, with their gRPC APIs.
- [sneakers-gateway](https://github.com/Sneakers-PAM/sneakers-gateway): the GraphQL and machine API for the web, mobile and MCP clients.
- [sneakers-identity](https://github.com/Sneakers-PAM/sneakers-identity): users, groups and SSO, with its gRPC API.
- [sneakers-audit](https://github.com/Sneakers-PAM/sneakers-audit): the tamper-evident audit trail.
- [sneakers-notify](https://github.com/Sneakers-PAM/sneakers-notify): the in-app notification inbox, with its gRPC API.
- [sneakers-connector](https://github.com/Sneakers-PAM/sneakers-connector): a pull-based worker that tests and rotates credentials on target systems (AD, SSH).
- [sneakers-sshbroker](https://github.com/Sneakers-PAM/sneakers-sshbroker): brokered SSH sessions without revealing keys.
- [sneakers-mcp](https://github.com/Sneakers-PAM/sneakers-mcp): the MCP server for AI agents, plus the `sneakers-run` and `sneakers-put` CLIs.

## 🖥️ Web

- [sneakers-web](https://github.com/Sneakers-PAM/sneakers-web): the web apps in one repo: staff, admin, appliance admin, maintenance, docs and the UI kit.

## 📦 Release and appliance

- [sneakers-release](https://github.com/Sneakers-PAM/sneakers-release): the release manifest, with every service, k0s and third-party component pinned to one version.
- [sneakers-appliance](https://github.com/Sneakers-PAM/sneakers-appliance): the appliance OS, a single-node k0s image with a closed shell, signed releases and two image slots, built on the [CryptOS](https://github.com/CryptOS-PKI) appliance design.

## 📱 Mobile

- [sneakers-android](https://github.com/Sneakers-PAM/sneakers-android): the Android app.
- [sneakers-ios](https://github.com/Sneakers-PAM/sneakers-ios): the iOS app, in Swift.

## 🌐 Website

- [website](https://github.com/Sneakers-PAM/website): the public website, with the project site and the system documentation.

## 🤝 Contributing

- [Contributing guide](https://github.com/Sneakers-PAM/.github/blob/main/.github/CONTRIBUTING.md), with the DCO sign-off
- [Code of Conduct](https://github.com/Sneakers-PAM/.github/blob/main/.github/CODE_OF_CONDUCT.md)
- [Security policy](https://github.com/Sneakers-PAM/.github/blob/main/.github/SECURITY.md)
- [Support](https://github.com/Sneakers-PAM/.github/blob/main/.github/SUPPORT.md)
- [Governance](https://github.com/Sneakers-PAM/.github/blob/main/GOVERNANCE.md) and [maintainers](https://github.com/Sneakers-PAM/.github/blob/main/MAINTAINERS.md)

## 📄 Licence

[Apache-2.0](https://github.com/Sneakers-PAM/.github/blob/main/LICENSE).
