

# Security Policy

## 🔒 Our Commitment

Security is at the core of AIS Forge. As an authentication infrastructure project, we take security vulnerabilities extremely seriously and are committed to working with security researchers to resolve issues responsibly.

---

## 🛡️ Supported Versions

As AIS Forge is currently in early development, security updates will be applied to the main branch. Once we reach a stable release, we will maintain the following support policy:

| Version | Supported          |
| ------- | ------------------ |
| main    | ✅ Active development |
| < 1.0   | ⚠️ Pre-release (not production ready) |

**Note**: AIS Forge is not yet production-ready. Please do not use it in production environments until version 1.0 is released.

---

## 🔍 Security Features

AIS Forge implements multiple layers of security:

### Cryptographic Security
- **Asymmetric key signing** using industry-standard algorithms
- **Automatic key rotation** with configurable intervals
- **Key versioning** via `kid` (Key ID) for seamless rotation
- **JWKS endpoint** for public key distribution

### Token Security
- **Short-lived access tokens** (default: 15 minutes)
- **Opaque refresh tokens** stored hashed in the database
- **Strict token rotation** on refresh (one-time use)
- **Token revocation** support
- **Token binding** to prevent token theft

### Data Protection
- **Argon2id password hashing** with configurable cost factor
- **No plaintext secrets** stored in the database
- **Prepared statements** to prevent SQL injection
- **Input validation** on all endpoints

### Infrastructure Security
- **Type-safe database queries** via Drizzle ORM
- **Environment-based configuration** (no hardcoded secrets)
- **Audit logging** for all authentication events
- **Rate limiting** on authentication endpoints (planned)

---

## 🚨 Reporting a Vulnerability

We greatly appreciate security researchers who help us maintain the security of AIS Forge.

### How to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them privately via:

1. **GitHub Security Advisories**
   - Go to the [Security tab](https://github.com/SkyZonDev/ais-forge/security)
   - Click "Report a vulnerability"
   - Fill out the form with details

### What to Include

A good security report should include:

- **Description** of the vulnerability
- **Impact** assessment (what can an attacker do?)
- **Steps to reproduce** the issue
- **Proof of concept** (if applicable)
- **Suggested fix** (if you have one)
- **Your name/handle** for credit (optional)

### Example Report Structure

```
Title: [Brief description of the vulnerability]

Severity: [Critical/High/Medium/Low]

Description:
[Detailed description of the vulnerability]

Impact:
[What could an attacker achieve with this vulnerability?]

Steps to Reproduce:
1. [First step]
2. [Second step]
3. [...]

Proof of Concept:
[Code, curl commands, or screenshots demonstrating the issue]

Suggested Fix:
[Your recommendations, if any]

Environment:
- Version: [commit hash or release version]
- Configuration: [relevant config details]
```

---

## ⏱️ Response Timeline

We are committed to responding promptly to security reports:

- **Initial response**: Within 48 hours
- **Status update**: Within 7 days
- **Fix timeline**: Depends on severity
  - **Critical**: 7-14 days
  - **High**: 14-30 days
  - **Medium**: 30-60 days
  - **Low**: Best effort

We will keep you informed throughout the process.

---

## 🏆 Disclosure Policy

We follow **coordinated disclosure**:

1. You report a vulnerability privately
2. We acknowledge and investigate
3. We develop and test a fix
4. We release the fix
5. We publicly disclose the issue (with credit to you, if desired)

We ask that you:

- Give us reasonable time to fix the issue before public disclosure
- Make a good faith effort to avoid privacy violations, data destruction, or service disruption
- Do not exploit the vulnerability beyond what's necessary to demonstrate it

---

## 🎁 Recognition

We believe in recognizing security researchers for their contributions:

- **Security Hall of Fame**: We maintain a list of researchers who have responsibly disclosed vulnerabilities
- **Public acknowledgment**: With your permission, we credit you in release notes and advisories
- **CVE assignment**: For qualifying vulnerabilities, we will request a CVE

### Hall of Fame

*No vulnerabilities reported yet. Be the first!*

---

## 🔐 Security Best Practices for Users

When self-hosting AIS Forge:

### Deployment
- ✅ Use HTTPS in production (required)
- ✅ Keep AIS Forge behind a firewall
- ✅ Use strong database passwords
- ✅ Enable database encryption at rest
- ✅ Regularly update dependencies
- ✅ Monitor logs for suspicious activity

### Configuration
- ✅ Use environment variables for secrets
- ✅ Set appropriate token TTLs
- ✅ Enable rate limiting
- ✅ Configure CORS carefully
- ✅ Rotate signing keys regularly
- ✅ Use strong password policies

### Operations
- ✅ Regularly backup your database
- ✅ Monitor for failed authentication attempts
- ✅ Review audit logs periodically
- ✅ Test your disaster recovery plan
- ✅ Keep AIS Forge updated

---

## 📚 Security Resources

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)

---

## 🔄 Security Updates

Security updates will be announced via:

- GitHub Security Advisories
- Release notes
- Project discussions

Subscribe to repository notifications to stay informed.

---

## ❓ Questions?

If you have questions about our security practices that don't involve reporting a vulnerability, please:

- Open a discussion in [GitHub Discussions](https://github.com/SkyZonDev/ais-forge/discussions)
- Tag it with the `security` label

---

## 📞 Contact

- **Project issues**: [GitHub Issues](https://github.com/SkyZonDev/ais-forge/issues)

---

<div align="center">

**Thank you for helping keep AIS Forge and its users safe!** 🙏

</div>
