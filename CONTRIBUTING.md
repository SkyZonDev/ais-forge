# Contributing to AIS Forge

🎉 **Thank you for your interest in contributing to AIS Forge!**

We're building a secure, self-hosted authentication core, and we welcome contributions from developers of all skill levels. Whether you're fixing a typo, implementing a feature, or suggesting improvements, your input is valuable.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Testing](#testing)
- [Documentation](#documentation)
- [Community](#community)

---

## 📜 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for everyone, regardless of:

- Age, body size, disability, ethnicity
- Gender identity and expression
- Level of experience
- Nationality, personal appearance, race
- Religion, sexual identity and orientation

### Our Standards

**Positive behavior includes:**

- ✅ Using welcoming and inclusive language
- ✅ Being respectful of differing viewpoints
- ✅ Gracefully accepting constructive criticism
- ✅ Focusing on what's best for the community
- ✅ Showing empathy towards others

**Unacceptable behavior includes:**

- ❌ Harassment, trolling, or insulting comments
- ❌ Personal or political attacks
- ❌ Publishing others' private information
- ❌ Any conduct that could be considered inappropriate in a professional setting

### Enforcement

Violations can be reported to the project maintainers at `conduct@yourproject.com`. All complaints will be reviewed and investigated promptly and fairly.

---

## 🚀 Getting Started

### Prerequisites

- **Node.js** 18+ and npm (or pnpm)
- **PostgreSQL** 14+
- **Git**
- A code editor (we recommend VS Code)

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/ais-forge.git
cd ais-forge

# Add upstream remote
git remote add upstream https://github.com/SkyZonDev/ais-forge.git
```

### Setup Development Environment

```bash
# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Edit .env with your local database credentials
# DATABASE_URL=postgres://postgres:password@localhost:5432/ais_forge_dev

# Run database migrations
npm run db:migrate

# Start development server
npm run dev
```

---

## 🤝 How to Contribute

### Types of Contributions

We welcome various types of contributions:

#### 🐛 Bug Reports
- Found a bug? Open an issue with detailed reproduction steps
- Include your environment details (OS, Node version, etc.)

#### ✨ Feature Requests
- Have an idea? Open a discussion first to gauge interest
- Explain the use case and expected behavior

#### 📝 Documentation
- Fix typos, clarify explanations, add examples
- Documentation is code too!

#### 🔧 Code Contributions
- Bug fixes
- New features
- Performance improvements
- Refactoring

#### 🧪 Testing
- Write tests for existing code
- Improve test coverage
- Report edge cases

---

## 💻 Development Workflow

### 1. Create a Branch

Always create a new branch for your work:

```bash
# Update your fork
git checkout main
git pull upstream main

# Create a feature branch
git checkout -b feat/your-feature-name

# Or for bug fixes
git checkout -b fix/bug-description
```

### 2. Make Your Changes

- Write clean, readable code
- Follow our coding standards (see below)
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes

```bash
# Run all tests
npm test

# Run specific test file
npm test -- path/to/test.spec.ts

# Run tests in watch mode
npm run test:watch

# Check test coverage
npm run test:coverage
```

### 4. Commit Your Changes

```bash
# Stage your changes
git add .

# Commit with a descriptive message
git commit -m "feat: add token revocation endpoint"
```

See [Commit Guidelines](#commit-guidelines) below.

### 5. Push and Create PR

```bash
# Push to your fork
git push origin feat/your-feature-name

# Then create a Pull Request on GitHub
```

---

## 📏 Coding Standards

### TypeScript

We use TypeScript for type safety. Follow these guidelines:

```typescript
// ✅ Good: Explicit types, clear naming
interface TokenPayload {
  sub: string;
  exp: number;
  iat: number;
}

function generateToken(payload: TokenPayload): string {
  // Implementation
}

// ❌ Bad: Implicit any, unclear naming
function gen(p: any) {
  // Implementation
}
```

### Code Style

We use Biome for consistent formatting:

```bash
# Check for linting errors
npm run lint

# Fix auto-fixable issues and format code
npm run lint:fix
```

**Key principles:**

- ✅ Use meaningful variable names
- ✅ Keep functions small and focused
- ✅ Write self-documenting code
- ✅ Add comments for complex logic
- ✅ Prefer immutability
- ✅ Handle errors explicitly

### File Structure

```
src/
├── api/          # API routes and controllers
├── core/         # Core business logic
├── db/           # Database schema and migrations
├── middleware/   # Express middleware
├── types/        # TypeScript type definitions
└── utils/        # Utility functions

tests/
├── unit/         # Unit tests
├── integration/  # Integration tests
└── fixtures/     # Test data and helpers
```

---

## 📝 Commit Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `ci`: CI/CD changes

### Examples

```bash
# Feature
git commit -m "feat(auth): add refresh token rotation"

# Bug fix
git commit -m "fix(tokens): prevent expired token reuse"

# Documentation
git commit -m "docs(readme): update installation instructions"

# Breaking change
git commit -m "feat(api)!: change token response structure

BREAKING CHANGE: The token endpoint now returns an object with
access_token and refresh_token fields instead of a flat structure."
```

### Rules

- ✅ Use present tense ("add feature" not "added feature")
- ✅ Use imperative mood ("move cursor to..." not "moves cursor to...")
- ✅ Lowercase first letter (except for breaking changes)
- ✅ No period at the end
- ✅ Keep subject line under 72 characters
- ✅ Reference issues/PRs in footer: `Fixes #123`

---

## 🔄 Pull Request Process

### Before Submitting

- ✅ Code compiles without errors
- ✅ All tests pass
- ✅ Linting passes
- ✅ Documentation is updated
- ✅ Commits follow conventional commits
- ✅ Branch is up to date with main

### PR Template

When creating a PR, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
How did you test this?

## Checklist
- [ ] Tests pass
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No new warnings
```

### Review Process

1. **Automated checks** run (tests, linting)
2. **Maintainer review** (usually within 2-3 days)
3. **Address feedback** if requested
4. **Approval and merge**

### What We Look For

- ✅ Code quality and readability
- ✅ Test coverage
- ✅ Security considerations
- ✅ Performance impact
- ✅ Documentation completeness
- ✅ Backward compatibility

---

## 🧪 Testing

### Writing Tests

We use Vitest for testing. Tests should be:

- **Clear**: Easy to understand what's being tested
- **Isolated**: No dependencies between tests
- **Repeatable**: Same result every time
- **Fast**: Quick to execute

```typescript
// Example test
import { describe, it, expect } from 'vitest';
import { generateToken } from './token';

describe('generateToken', () => {
  it('should generate a valid JWT', () => {
    const payload = { sub: 'user123', exp: Date.now() + 3600 };
    const token = generateToken(payload);
    
    expect(token).toBeDefined();
    expect(typeof token).toBe('string');
    expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
  });

  it('should throw error for expired token', () => {
    const payload = { sub: 'user123', exp: Date.now() - 3600 };
    
    expect(() => generateToken(payload)).toThrow('Token expired');
  });
});
```

### Test Coverage

Aim for high test coverage, especially for:

- Authentication logic
- Token generation and validation
- Cryptographic operations
- Database operations
- API endpoints

```bash
# View coverage report
npm run test:coverage
```

---

## 📚 Documentation

Good documentation is crucial for a security project.

### Code Comments

```typescript
/**
 * Generates a signed JWT access token.
 * 
 * @param payload - The token payload containing user identity
 * @param options - Optional configuration (expiry, audience, etc.)
 * @returns Signed JWT string
 * @throws TokenGenerationError if signing fails
 */
function generateAccessToken(
  payload: TokenPayload,
  options?: TokenOptions
): string {
  // Implementation
}
```

### README and Guides

- Keep the README up-to-date
- Add examples for new features
- Document configuration options
- Explain security considerations

### API Documentation

- Document all endpoints
- Include request/response examples
- List possible error codes
- Note authentication requirements

---

## 💬 Community

### Getting Help

- 💭 **Questions**: [GitHub Discussions](https://github.com/SkyZonDev/ais-forge/discussions)
- 🐛 **Bugs**: [GitHub Issues](https://github.com/SkyZonDev/ais-forge/issues)
- 💡 **Ideas**: [GitHub Discussions - Ideas](https://github.com/SkyZonDev/ais-forge/discussions/categories/ideas)

### Communication Channels

- **GitHub Discussions**: For questions and general discussion
- **GitHub Issues**: For bug reports and feature requests
- **Pull Requests**: For code contributions

### Stay Updated

- ⭐ Star the repository
- 👀 Watch for updates
- 📰 Follow release notes

---

## 🏆 Recognition

Contributors are recognized in:

- The project README
- Release notes
- GitHub insights
- Our hearts ❤️

---

## 📞 Questions?

If you have questions about contributing:

- Open a [discussion](https://github.com/SkyZonDev/ais-forge/discussions)

---

<div align="center">

**Every contribution makes AIS Forge better. Thank you!** 🙏

[Start Contributing →](https://github.com/SkyZonDev/ais-forge)

</div>
