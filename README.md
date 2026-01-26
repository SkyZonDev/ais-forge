
<div align="center">

# AIS Forge: Self-Hosted Authentication Core

[![Python](https://img.shields.io/badge/Fastify-5.6.2-3776AB?style=flat-square&logo=fastify&logoColor=white)](https://www.python.org/downloads/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14%2B-336791?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Drizzle](https://img.shields.io/badge/Drizzle-ORM-C5F74F?style=flat-square&logo=drizzle&logoColor=black)](https://orm.drizzle.team/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-Apache--2.0-green?style=flat-square)](LICENSE.md)
[![CI](https://img.shields.io/github/actions/workflow/status/SkyZonDev/ais-forge/ci.yml?style=flat-square&logo=github&label=CI)](https://github.com/SkyZonDev/ais-forge/actions)

</div>

> **A self-hosted authentication core for developers who demand control**

AIS Forge is a security-first, API-driven authentication server designed for backend services, internal platforms, and custom applications. No vendor lock-in. No unnecessary protocols. Just complete control over your authentication infrastructure.

---

## ⚠️ Project Status

**Early development — not production ready**

The project is under active design and implementation. APIs, data models, and cryptographic choices may evolve. Star and watch this repository to follow progress.

---

## 🎯 Why AIS Forge?

Modern authentication solutions force you to choose between:

- **Third-party platforms** (Auth0, Firebase, Cognito) → vendor lock-in, external dependencies, limited control
- **Interactive IdPs** (OAuth 2.0 / OIDC) → unnecessary redirects, consent screens, and complexity for backend systems

**AIS Forge fills the gap** by providing a headless, self-hosted authentication server built for infrastructure, not consumers.

### What Makes AIS Forge Different

- 🏠 **Fully self-hosted** — your data, your infrastructure, your rules
- 🔌 **API-first** — no UI, no redirects, no browser flows
- 🔒 **Security-first** — modern cryptography, short-lived tokens, automatic key rotation
- 🎯 **Purpose-built** — optimized for backend services and internal tools
- 📦 **Zero bloat** — no unnecessary protocols or abstractions

---

## ✨ Features

### Core Authentication

- **JWT-based access tokens** with asymmetric signing
- **Opaque refresh tokens** with strict rotation
- **Automatic key rotation** with JWKS distribution
- **Token revocation** and audit trails

### Security

- 🔐 Secrets never stored in plaintext
- 🔑 Asymmetric cryptography with `kid`-based key identification
- ⏱️ Short-lived tokens with configurable TTLs
- 🔄 Refresh token rotation on every use
- 📝 Full audit logging

### Infrastructure

- 🐘 PostgreSQL with Drizzle ORM
- 🚀 Type-safe schema and queries
- 📊 Explicit data models
- 🔍 Transparent storage

---

## 🏗️ Architecture

AIS Forge adopts proven cryptographic patterns without the overhead of interactive protocols:

```
┌─────────────────┐
│  Your Backend   │
│   Application   │
└────────┬────────┘
         │ HTTP API
         ▼
┌─────────────────┐
│   AIS Forge     │
│  Auth Server    │
├─────────────────┤
│ • Identity Mgmt │
│ • Token Issuance│
│ • Key Rotation  │
│ • JWKS Endpoint │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   PostgreSQL    │
│   + Drizzle     │
└─────────────────┘
```

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/SkyZonDev/ais-forge.git
cd ais-forge

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your database credentials

# Run migrations
npm run db:migrate

# Start the server
npm run dev
```

---

## 📖 Usage Example

```javascript
// Create a new identity
const identity = await fetch('http://localhost:3000/api/identities', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'developer',
    password: 'secure-password'
  })
});

// Authenticate
const auth = await fetch('http://localhost:3000/api/auth/token', {
  method: 'POST',
  body: JSON.stringify({
    username: 'developer',
    password: 'secure-password'
  })
});

const { access_token, refresh_token } = await auth.json();

// Use the access token
const resource = await fetch('http://localhost:3000/api/protected', {
  headers: {
    'Authorization': `Bearer ${access_token}`
  }
});

// Refresh when needed
const refreshed = await fetch('http://localhost:3000/api/auth/refresh', {
  method: 'POST',
  body: JSON.stringify({ refresh_token })
});
```

---

## 🎯 Use Cases

AIS Forge is ideal for:

- ✅ Custom authentication backends
- ✅ Internal company platforms
- ✅ Multi-project developer ecosystems
- ✅ Self-hosted SaaS backends
- ✅ Microservices requiring centralized auth
- ✅ Infrastructure-first environments

AIS Forge is **not** for:

- ❌ Consumer-facing identity providers
- ❌ Social login or SSO platforms
- ❌ Replacing Google/GitHub login
- ❌ Browser[template.md](../../Documents/WORKSTATION/DPS/dps-solution/.gitlab/merge_request_templates/template.md)-based redirect flows

---

## 🗺️ Roadmap

- [x] Core authentication API
- [x] JWKS endpoint
- [ ] Token management and rotation (in progress)
- [ ] Multi-factor authentication support
- [ ] API key authentication
- [ ] Session management
- [ ] Comprehensive audit logging
- [ ] Admin API
- [ ] Docker deployment
- [ ] Kubernetes Helm charts

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 🔒 Security

Security is our top priority. If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

---

## 📄 License

This project is licensed under the MIT License - see [LICENSE.md](LICENSE.md) for details.

---

## 🙏 Acknowledgments

AIS Forge draws inspiration from modern authentication best practices while focusing on simplicity and control. While we don't implement OIDC or OAuth 2.0, we adopt proven cryptographic patterns where appropriate.

---

## 📬 Contact

- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/ais-forge/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/yourusername/ais-forge/discussions)
- 📧 Email: jp.dupuis@dps-solution.com

---

<div align="center">

**Built with ❤️ for developers who value control**

[⭐ Star us on GitHub](https://github.com/yourusername/ais-forge)

</div>
