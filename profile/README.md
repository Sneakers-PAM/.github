<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/sneakers-mark-dark.svg">
    <img src="assets/sneakers-mark-light.svg" alt="Sneakers-PAM mark" width="96">
  </picture>
</p>

# Sneakers-PAM™ 👟

> 🔐 Open-source privileged access management, built as a set of small services.

Sneakers-PAM is an open-source, Apache-2.0 licensed privileged access management
system. It keeps credentials in a vault, tests and rotates them on the systems they
belong to, hands them out through approvals, check-out and brokered SSH sessions, and
records every access in a tamper-evident audit trail. It's built as a set of small
services rather than one monolith, with web, mobile and MCP clients, and runs on
Kubernetes or as a single-node appliance.

🏠 **Home:** [sneakers-pam.com](https://sneakers-pam.com)

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

## 🧪 Development

- [sneakers-mock-server](https://github.com/Sneakers-PAM/sneakers-mock-server): a standalone in-memory mock of the whole gateway API, shared by the web and mobile apps.

## 📦 Release and appliance

- [sneakers-release](https://github.com/Sneakers-PAM/sneakers-release): the release manifest, with every service, k0s and third-party component pinned to one version.
- [sneakers-appliance](https://github.com/Sneakers-PAM/sneakers-appliance): the appliance OS, a single-node k0s image with a closed shell, signed releases and two image slots.

## 📱 Mobile

- [sneakers-android](https://github.com/Sneakers-PAM/sneakers-android): the Android app.
- [sneakers-ios](https://github.com/Sneakers-PAM/sneakers-ios): the iOS app, in Swift.

## 🌐 Website

- [docs](https://github.com/Sneakers-PAM/docs): the source of the system documentation.
- [website](https://github.com/Sneakers-PAM/website): the source of the product site.

## 🤝 Contributing

- [Contributing guide](https://github.com/Sneakers-PAM/.github/blob/main/.github/CONTRIBUTING.md), with the DCO sign-off
- [Code of Conduct](https://github.com/Sneakers-PAM/.github/blob/main/.github/CODE_OF_CONDUCT.md)
- [Security policy](https://github.com/Sneakers-PAM/.github/blob/main/.github/SECURITY.md)
- [Support](https://github.com/Sneakers-PAM/.github/blob/main/.github/SUPPORT.md)
- [Governance](https://github.com/Sneakers-PAM/.github/blob/main/GOVERNANCE.md) and [maintainers](https://github.com/Sneakers-PAM/.github/blob/main/MAINTAINERS.md)

## 📄 Licence

[Apache-2.0](https://github.com/Sneakers-PAM/.github/blob/main/LICENSE).

## ™️ Trademarks

Sneakers-PAM™ and the Sneakers-PAM logo are trademarks of the rabbit hole tech, llc. The code is licensed under Apache-2.0; the licence does not grant rights to the names or logos. See [TRADEMARKS.md](https://github.com/Sneakers-PAM/.github/blob/main/TRADEMARKS.md) for the usage policy. Applications to register these trademarks are being prepared; full registered (®) protection is pending until they are granted.
