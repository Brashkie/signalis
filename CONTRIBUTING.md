# Contributing to @brashkie/signalis

Thanks for your interest in contributing! 🎉

This document explains how to get up and running, what we expect from contributions, and how to make changes that get merged smoothly.

---

## 📑 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Testing](#testing)
- [Commit Conventions](#commit-conventions)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)
- [Security](#security)

---

## Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

---

## Getting Started

### Prerequisites

- **Node.js:** 18.x, 20.x, 22.x, or 24.x (we test on all)
- **npm:** 9.x or later
- **Git**

### Setup

```bash
# Clone
git clone https://github.com/Brashkie/signalis.git
cd signalis

# Install
npm install

# Verify it builds and tests pass
npm run lint
npm run typecheck
npm test
npm run build
```

If all of these pass, you're ready to contribute! 🚀

---

## Development Workflow

### 1. Fork & Branch

```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR-USERNAME/signalis.git
cd signalis

# Add upstream remote
git remote add upstream https://github.com/Brashkie/signalis.git

# Create a feature branch
git checkout -b feat/my-new-feature
```

Use descriptive branch prefixes:
- `feat/...` — new features
- `fix/...` — bug fixes
- `docs/...` — documentation only
- `refactor/...` — code restructuring
- `test/...` — adding/updating tests
- `chore/...` — build, CI, tooling

### 2. Make Changes

Edit code in `src/` and tests in `__tests__/`.

### 3. Verify

```bash
# Lint
npm run lint

# Typecheck
npm run typecheck

# Tests
npm test

# Coverage (optional, but appreciated)
npm run test:coverage

# Build (to catch packaging issues)
npm run build
```

All of these MUST pass before submitting a PR.

### 4. Commit & Push

See [Commit Conventions](#commit-conventions) below.

### 5. Open a PR

Submit a Pull Request from your fork. The PR template will guide you through what's needed.

---

## Code Style

### TypeScript

- **Strict mode is mandatory.** All code must pass `npm run typecheck`.
- **No `any`** unless absolutely necessary (and explained in a comment).
- **Branded types** for security-sensitive values (`PublicKey`, `PrivateKey`, etc.).
- **No `console.log`** in committed code (except docs/examples). Use proper error handling.
- **JSDoc** for all public APIs.

### Formatting

We use **Prettier** for consistent formatting:

```bash
# Auto-format your changes
npm run format
```

### Linting

ESLint catches common issues:

```bash
npm run lint
```

### Naming

- **Classes:** PascalCase (`IdentityKeyPair`)
- **Functions / variables:** camelCase (`generateKeyPair`)
- **Constants:** UPPER_SNAKE_CASE (`PUBLIC_KEY_SIZE`)
- **Types / interfaces:** PascalCase (`SerializedKeyPair`)
- **Private members:** Either `#` or `_prefix` (we use `_` for consistency)
- **Files:** kebab-case (`identity-key.ts`)

### Comments

- Explain **WHY**, not WHAT (the code shows what).
- Reference specs / RFCs when implementing crypto: `// RFC 8032, Section 5.1.6`
- Mark unsafe code: `// SECURITY: Constant-time comparison required here`

---

## Testing

### Test Philosophy

- **Every bug fix needs a regression test**
- **Every new feature needs tests**
- **Crypto code needs round-trip tests + negative tests**

### Writing Tests

Tests live in `__tests__/` and use [Vitest](https://vitest.dev).

```typescript
import { describe, it, expect } from 'vitest';
import { IdentityKeyPair } from '../src/identity';

describe('IdentityKeyPair', () => {
  it('generates a 32-byte public key', () => {
    const id = IdentityKeyPair.generate();
    expect(id.publicKey.length).toBe(32);
  });

  it('throws on bad input', () => {
    expect(() => IdentityKeyPair.fromKeys(Buffer.alloc(10), Buffer.alloc(32)))
      .toThrow(ValidationError);
  });
});
```

### Required Test Patterns (for crypto code)

```typescript
// 1. Round-trip
const x = encrypt(plaintext);
expect(decrypt(x)).toEqual(plaintext);

// 2. Negative (tampering)
const ct = encrypt(plaintext);
ct[0] ^= 0xff;
expect(() => decrypt(ct)).toThrow();

// 3. Cross-key (Mallory can't forge)
const sig = aliceKey.sign(msg);
expect(bobKey.toPublic().verifyBool(msg, sig)).toBe(false);

// 4. Known test vectors (when applicable)
const known = Buffer.from('e3b0c44298fc...', 'hex'); // NIST vector
expect(sha256(Buffer.alloc(0)).equals(known)).toBe(true);
```

### Running Tests

```bash
# All tests
npm test

# Watch mode (re-runs on file changes)
npm run test:watch

# UI mode (interactive)
npm run test:ui

# Coverage
npm run test:coverage
```

### Coverage Targets

- **Lines:** 90%+
- **Branches:** 85%+
- **Functions:** 95%+

---

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

<optional body>

<optional footer>
```

### Types

- `feat` — new feature
- `fix` — bug fix
- `docs` — documentation only
- `refactor` — code change that neither fixes a bug nor adds a feature
- `perf` — performance improvement
- `test` — adding/updating tests
- `build` — build system or dependencies
- `ci` — CI configuration
- `chore` — misc tasks

### Scope (optional)

The package, module, or area being changed:

- `identity`, `prekeys`, `x3dh`, `ratchet`, `crypto`, `types`, `errors`, `constants`

### Examples

```
feat(identity): add XEd25519 signing methods

Adds sign()/verify()/verifyBool() to IdentityKeyPair and PublicIdentityKey,
using the underlying XEd25519 primitive from signalis-core v0.2.0.

Closes #42
```

```
fix(crypto): validate AAD size in aesGcmEncryptWithAad

The previous version would silently truncate AAD over 2^32 bytes.

Fixes #58
```

```
docs(readme): add comparison table with libsignal-node
```

### Breaking Changes

Add `!` after the type/scope:

```
feat(api)!: rename IdentityKey to IdentityKeyPair

BREAKING CHANGE: The class previously named IdentityKey is now
IdentityKeyPair to better reflect that it contains both keys.
```

---

## Pull Request Process

### Before You Open a PR

1. ✅ All tests pass (`npm test`)
2. ✅ Typecheck passes (`npm run typecheck`)
3. ✅ Lint passes (`npm run lint`)
4. ✅ Build succeeds (`npm run build`)
5. ✅ You've added tests for new code
6. ✅ You've updated docs if needed
7. ✅ You've added a CHANGELOG entry (under `## [Unreleased]`)

### When You Open a PR

- **Title:** Use Conventional Commits format
- **Description:** Use the template (it auto-populates)
- **Link issues:** "Closes #123" or "Related to #456"
- **Screenshots:** For UI/output changes
- **Performance notes:** For perf-related changes

### Review Process

- A maintainer will respond within 7 days
- Address feedback in follow-up commits (we squash on merge)
- Once approved, we'll merge

### After Merge

- Your changes will be included in the next release
- Major features get called out in the CHANGELOG
- Significant contributions get a shoutout in release notes 🎉

---

## Reporting Issues

### Bug Reports

Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md). Include:

- Versions (Node, OS, signalis, signalis-core)
- Minimal reproduction
- Expected vs actual behavior
- Error messages / stack traces

### Feature Requests

Use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md). Tell us:

- What problem this solves
- Proposed API (rough sketch)
- Alternatives considered

### Questions

For questions, use [GitHub Discussions](https://github.com/Brashkie/signalis/discussions) instead of issues.

---

## Security

**Do NOT report security vulnerabilities in public issues.**

See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## What Makes a Good Contribution?

### 🟢 Great contributions

- Fix bugs with regression tests
- Add features from the roadmap with tests + docs
- Improve docs (typos, clarity, examples)
- Performance improvements with benchmarks
- New test coverage for existing code

### 🟡 Discuss first

- Breaking API changes
- Adding new dependencies
- Major architectural changes
- New crypto primitives

### 🔴 Avoid

- "Drive-by" formatting-only PRs
- PRs that mix unrelated changes
- Changes that disable failing tests
- Unsafe crypto patterns ("trust me, this is fine")

---

## Getting Help

- [GitHub Discussions](https://github.com/Brashkie/signalis/discussions) — Q&A
- [GitHub Issues](https://github.com/Brashkie/signalis/issues) — bugs & feature requests
- [ROADMAP.md](ROADMAP.md) — what we're working on
- [API.md](API.md) — full API reference
- [EXAMPLES.md](EXAMPLES.md) — practical examples

---

🔐 + ❤️ [Hepein Oficial](https://github.com/Brashkie)
