<div align="center">

# @brashkie/signalis

**Implementación del Protocolo Signal en TypeScript, lista para producción.**
**X3DH · Double Ratchet · Sender Keys · Gestión de Identidad.**

[![npm version](https://img.shields.io/npm/v/@brashkie/signalis.svg)](https://www.npmjs.com/package/@brashkie/signalis)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node.js Version](https://img.shields.io/node/v/@brashkie/signalis.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-6.0-3178c6.svg)](https://www.typescriptlang.org)
[![Tests](https://img.shields.io/badge/tests-passing-success.svg)](#-testing)
[![CI](https://github.com/Brashkie/signalis/actions/workflows/ci.yml/badge.svg)](https://github.com/Brashkie/signalis/actions/workflows/ci.yml)
[![Powered by Rust](https://img.shields.io/badge/powered_by-Rust-orange.svg)](https://www.rust-lang.org)

[English](README.md) · **Español**

Hecho con 🔐 + ❤️ por [Hepein Oficial](https://github.com/Brashkie)

</div>

---

## 📑 Tabla de Contenidos

- [¿Qué es Signalis?](#-qué-es-signalis)
- [Novedades en v0.2.0](#-novedades-en-v020)
- [Características](#-características)
- [¿Por qué Signalis?](#-por-qué-signalis)
- [Comparación con Alternativas](#-comparación-con-alternativas)
- [Instalación](#-instalación)
- [Inicio Rápido](#-inicio-rápido)
- [Resumen de la API](#-resumen-de-la-api)
- [Arquitectura](#-arquitectura)
- [Seguridad](#-seguridad)
- [Testing](#-testing)
- [Compilar desde Código Fuente](#-compilar-desde-código-fuente)
- [Roadmap](#-roadmap)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)

---

## ✨ ¿Qué es Signalis?

`@brashkie/signalis` es una **implementación en TypeScript del Protocolo Signal** — el mismo protocolo de cifrado extremo a extremo que usan Signal, WhatsApp y Skype. Provee:

- 🔑 **Identity Keys** — Gestión de identidad de largo plazo con firma XEd25519
- 🔁 **PreKey Bundles** — Establecimiento asíncrono de sesiones (X3DH)
- 🪜 **Double Ratchet** — Forward y backward secrecy para cada mensaje
- 👥 **Sender Keys** — Mensajería grupal eficiente
- 💾 **Capa de Storage** — Persistencia pluggable para sesiones/llaves
- 🛡️ **Construido sobre `@brashkie/signalis-core`** — Primitivas criptográficas en Rust nativo

> **Parte del ecosistema [Hepein](https://github.com/Brashkie).**
> Base para `@brashkie/waproto` (Protocolo WhatsApp) y eventualmente una alternativa a Baileys construida desde cero.

---

## 🎉 Novedades en v0.2.0

**v0.2.0 trae firmas digitales reales a las identity keys** — reemplazando el enfoque placeholder de v0.1.0 con XEd25519 propio (estilo Signal).

| Nuevo | Descripción |
|-------|-------------|
| 🆕 **`identity.sign(message)`** | Firma datos arbitrarios con tu identity key (XEd25519) |
| 🆕 **`identity.signWithRandom(message, random)`** | Firma determinística (para tests) |
| 🆕 **`identity.verify(msg, sig)`** | Verifica una firma (lanza SignatureError) |
| 🆕 **`identity.verifyBool(msg, sig)`** | Verifica una firma (devuelve boolean) |
| 🆕 **`alicePub.verify(msg, sig)`** | Verifica solo con un `PublicIdentityKey` |
| 🆕 **`alicePub.verifyBool(msg, sig)`** | Versión booleana |
| 🆕 **Wrappers Ed25519** | `signEd25519`, `verifyEd25519` (separados de Curve25519) |
| 🆕 **AES-GCM con AAD** | `aesGcmEncryptWithAad` / `aesGcmDecryptWithAad` |
| 🆕 **`SignatureError`** | Tipo de error dedicado para fallos de verificación |

Bumpea la dependencia: `@brashkie/signalis-core` de `^0.1.0` → `^0.2.0`.

**100% compatible hacia atrás.** Todas las APIs de v0.1.0 siguen funcionando.

---

## 🚀 Características

| Característica | v0.2.0 | Sprint |
|----------------|--------|--------|
| 🔑 **Identity Key Pair** (Curve25519) | ✅ | 1 |
| ✍️ **Firma XEd25519 en identity keys** | ✅ NUEVO | 1 Parte 2 |
| 🛡️ **Tipos branded** (PublicKey vs PrivateKey en tiempo de compilación) | ✅ | 1 |
| 🎯 **Type-safe** con soporte TypeScript 6.0 completo | ✅ | 1 |
| 📦 **Paquete dual ESM/CJS** | ✅ | 1 |
| 🧪 **Suite de tests exhaustiva** con vectores RFC | ✅ | 1 |
| 🔐 **Defaults seguros** (no fuga de private keys en toString) | ✅ | 1 |
| 💾 **Serialización/deserialización** (compatible con JSON) | ✅ | 1 |
| 🔁 **PreKey Bundles** (One-time + Signed) | 🚧 | 2 |
| 🤝 **X3DH** (Extended Triple Diffie-Hellman) | 🚧 | 2 |
| 🪜 **Double Ratchet** (forward + backward secrecy) | 🚧 | 3 |
| 💾 **Capa de storage pluggable** | 🚧 | 4 |
| 👥 **Sender Keys** (mensajería grupal) | 🚧 | 5 |

---

## 🤔 ¿Por qué Signalis?

### vs. Hacer tu propia criptografía

```
❌ Hacerla a mano: bugs, side-channels, footguns por todos lados
✅ Signalis: construido sobre primitivas Rust auditadas (RustCrypto, dalek-cryptography)
```

### vs. Usar `crypto` nativo de Node

```
❌ node:crypto: bajo nivel, fácil de usar mal (reutilización de nonces, confusión de modos)
✅ Signalis: API de alto nivel con semántica del Protocolo Signal
```

### vs. Otras librerías del Protocolo Signal

| Necesidad | Signalis | libsignal-node | @privacyresearch/libsignal-protocol-typescript |
|-----------|----------|----------------|------------------------------------------------|
| **TypeScript-first** | ✅ Tipos branded + modo strict | 🟡 Tiene tipos | 🟡 Tiene tipos |
| **Install JS puro** | ✅ (signalis-core depende de nativo) | ❌ Requiere toolchain Rust | ✅ |
| **Velocidad** | 🔥 Rust nativo via NAPI | 🔥 Rust nativo | 🐢 JS puro (lento) |
| **Mantenimiento activo** | ✅ Activo | 🟡 Esporádico | ❌ Stale |
| **Dual ESM/CJS** | ✅ | ❌ | ❌ |
| **API moderna** | ✅ Basada en clases, async-friendly | 🟡 Estilo viejo | 🟡 Con muchos callbacks |
| **Licencia** | Apache-2.0 | GPL-3.0 | GPL-3.0 |

---

## 📊 Comparación con Alternativas

### Performance

Benchmarks (Node 22, x86_64, promedio de 10k iteraciones):

| Operación | Signalis (via Rust) | tweetnacl | libsignal-protocol-typescript |
|-----------|---------------------|-----------|-------------------------------|
| Generación de identity keypair | **~50,000/seg** | ~3,000/seg | ~2,000/seg |
| Sign (XEd25519) | **~25,000/seg** | N/A | ~1,500/seg |
| Verify (XEd25519) | **~10,000/seg** | N/A | ~800/seg |
| ECDH (X25519) | **~30,000/seg** | ~2,000/seg | ~1,500/seg |

> Números de los benchmarks de `@brashkie/signalis-core`. Resultados pueden variar.

### Tamaño del Bundle

```
@brashkie/signalis:              ~15 KB minificado
@brashkie/signalis-core (nativo): ~400 KB por plataforma (un binario)

Total instalado: ~600 KB (vs 1.5 MB+ para alternativas JS puro)
```

### Comparación de Código

**Otras librerías** (JS puro, verboso, sin tipos):
```javascript
const SignalProtocolStore = require('./SignalProtocolStore');
const libsignal = require('libsignal-protocol-typescript');
const store = new SignalProtocolStore();
await libsignal.KeyHelper.generateIdentityKeyPair().then(kp => {
  // continúa la pirámide del horror...
});
```

**Signalis** (TypeScript-first, limpio):
```typescript
import { IdentityKeyPair } from '@brashkie/signalis';

const identity = IdentityKeyPair.generate();
const sig = identity.sign(Buffer.from('hello'));
identity.verify(Buffer.from('hello'), sig);
```

---

## 📦 Instalación

```bash
npm install @brashkie/signalis
```

Esto también instala `@brashkie/signalis-core` (primitivas criptográficas), que usa binarios nativos pre-compilados para:

- ✅ Windows x64 (MSVC), Windows arm64 (MSVC)
- ✅ macOS x64 (Intel), macOS arm64 (Apple Silicon)
- ✅ Linux x64 (glibc + musl), Linux arm64 (glibc)

**No requiere toolchain de Rust** para instalar.

### Requisitos

- **Node.js:** 18.x, 20.x, 22.x, o 24.x
- **TypeScript** (opcional pero recomendado): 6.0+

---

## 🚀 Inicio Rápido

### 1. Generar una Identity Key

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';

// Genera al registrar al usuario (una sola vez, guarda de forma segura)
const alice = IdentityKeyPair.generate();

console.log('Mi fingerprint:', alice.fingerprint());
// → "a1b2c3d4e5f6..." (hex de 64 caracteres)

console.log('Corto:', alice.shortFingerprint());
// → "a1b2c3d4e5f60718"
```

### 2. Persistir de Forma Segura

```typescript
// Serializa para guardar
const data = alice.serialize();
// → { publicKey: "abc123...", privateKey: "def456..." }

// ⚠️ Guarda en storage encriptado (ej: AWS KMS, keychain del SO, DB encriptada)
await myEncryptedDB.save('user-identity', data);

// Después: restaurar
const stored = await myEncryptedDB.load('user-identity');
const alice = IdentityKeyPair.deserialize(stored);
```

### 3. Firmar Mensajes (NUEVO en v0.2.0)

```typescript
const alice = IdentityKeyPair.generate();
const message = Buffer.from('Autorizo esta transacción');

const signature = alice.sign(message);
// → Buffer de 64 bytes

// Cualquiera con la public key de Alice puede verificar:
const alicePub = alice.toPublic();
alicePub.verify(message, signature); // lanza SignatureError si es inválida

// O usar la versión booleana (sin throw):
if (alicePub.verifyBool(message, signature)) {
  console.log('✅ Mensaje auténtico de Alice');
}
```

### 4. Compartir Public Keys

```typescript
// Envía la public key de Alice por la red
const alicePublicHex = alice.toPublic().toHex();
sendToContact(alicePublicHex);

// Lado del receptor: reconstruir
const alicePub = PublicIdentityKey.fromHex(alicePublicHex);

// Verifica el fingerprint con el usuario
console.log('Verifica que esto coincide con Alice:', alicePub.fingerprint());
```

### 5. Ejemplo Completo de Canal Autenticado

```typescript
import { IdentityKeyPair, PublicIdentityKey } from '@brashkie/signalis';

// ── Lado de Alice ────────────────────────────────────────────────────
const alice = IdentityKeyPair.generate();
const message = Buffer.from('¡Hola, mundo seguro!');
const signature = alice.sign(message);

// Enviar a Bob: alicePublicKey, message, signature
const payload = {
  from: alice.toPublic().toHex(),
  body: message.toString('hex'),
  sig: signature.toString('hex'),
};

// ── Lado de Bob ──────────────────────────────────────────────────────
const aliceKey = PublicIdentityKey.fromHex(payload.from);
const receivedMsg = Buffer.from(payload.body, 'hex');
const receivedSig = Buffer.from(payload.sig, 'hex');

try {
  aliceKey.verify(receivedMsg, receivedSig);
  console.log('✅ Mensaje auténtico:', receivedMsg.toString());
} catch (e) {
  console.error('❌ Firma falsificada o mensaje alterado!');
}
```

---

## 📚 Resumen de la API

### `IdentityKeyPair`

La identidad de largo plazo de un usuario. Se genera **una vez** al registrarse, se guarda de forma segura, nunca se rota.

```typescript
class IdentityKeyPair {
  readonly publicKey: PublicKey;     // 32 bytes, con brand
  readonly privateKey: PrivateKey;   // 32 bytes, con brand

  // ─── Construcción ────────────────────────────────────────────────
  static generate(): IdentityKeyPair;
  static fromKeys(pub: Buffer, priv: Buffer): IdentityKeyPair;
  static deserialize(data: SerializedKeyPair): IdentityKeyPair;

  // ─── Firma (NUEVO v0.2.0) ────────────────────────────────────────
  sign(message: Buffer): Signature;
  signWithRandom(message: Buffer, random: Buffer): Signature;
  verify(message: Buffer, signature: Buffer): void;        // lanza si inválida
  verifyBool(message: Buffer, signature: Buffer): boolean;

  // ─── Accesores ───────────────────────────────────────────────────
  toPublic(): PublicIdentityKey;
  fingerprint(): string;              // SHA-256 hex de la public key
  shortFingerprint(): string;         // primeros 16 caracteres hex
  equals(other: IdentityKeyPair | PublicIdentityKey): boolean;

  // ─── Serialización ───────────────────────────────────────────────
  serialize(): SerializedKeyPair;     // { publicKey, privateKey } como hex
  toJSON(): { type, publicKey };      // SEGURO — excluye private key
  toString(): string;                 // SEGURO — solo fingerprint corto
}
```

### `PublicIdentityKey`

Solo la parte pública — segura para compartir con cualquiera.

```typescript
class PublicIdentityKey {
  readonly publicKey: PublicKey;

  // ─── Construcción ────────────────────────────────────────────────
  constructor(pubKey: Buffer);
  static fromHex(hex: string): PublicIdentityKey;
  static fromBase64(b64: string): PublicIdentityKey;

  // ─── Verificación (NUEVO v0.2.0) ─────────────────────────────────
  verify(message: Buffer, signature: Buffer): void;       // lanza SignatureError
  verifyBool(message: Buffer, signature: Buffer): boolean;

  // ─── Salida ──────────────────────────────────────────────────────
  toHex(): string;
  toBase64(): string;
  fingerprint(): string;
  shortFingerprint(): string;
  equals(other: PublicIdentityKey | IdentityKeyPair): boolean;
}
```

### Errores

```typescript
class SignalisError extends Error
├── ValidationError       // Input inválido (tamaño/tipo erróneo)
├── SignatureError        // Firma inválida ← NUEVO v0.2.0
├── KeyError              // Generación/manipulación de llaves
├── PreKeyError           // Específico de PreKey (Sprint 2)
├── SerializationError    // Encoding/decoding
├── ProtocolError         // Violación de protocolo
└── SessionError          // Manejo de sesión (Sprint 3+)
```

### Primitivas Criptográficas (avanzado)

Para operaciones de bajo nivel, el namespace `crypto` re-exporta `@brashkie/signalis-core`:

```typescript
import { crypto } from '@brashkie/signalis';

// XEd25519 (estilo Signal)
const sig = crypto.signXEd25519(privateKey, message);
crypto.verifyXEd25519(publicKey, message, sig);

// Ed25519 estándar (determinístico, RFC 8032)
const ed = crypto.generateEd25519KeyPair();
const sig = crypto.signEd25519(ed.privateKey, message);

// ECDH
const shared = crypto.diffieHellman(privateKey, peerPublicKey);

// HKDF
const key = crypto.hkdf(salt, ikm, info, 32);

// AES-256-GCM con AAD (NUEVO v0.2.0)
const ct = crypto.aesGcmEncryptWithAad(key, nonce, plaintext, header);
const pt = crypto.aesGcmDecryptWithAad(key, nonce, ct, header);
```

Ver [API.md](API.md) para la referencia completa.

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│  Tu Aplicación                                               │
│  (Cliente de chat, dispositivo IoT, servidor, etc.)         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  @brashkie/signalis  ← ESTÁS AQUÍ                            │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Identity   │  │   PreKeys   │  │   Session   │         │
│  │   Módulo    │  │  (Sprint 2) │  │ (Sprint 3+) │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                              │
│  • IdentityKeyPair (firma XEd25519)                         │
│  • PublicIdentityKey (verificación)                          │
│  • Tipos branded (seguridad en tiempo de compilación)        │
│  • Errores tipados con códigos                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  @brashkie/signalis-core (Rust + NAPI)                       │
│                                                              │
│  Curve25519 · Ed25519 · XEd25519 · HKDF · AES-GCM           │
│  HMAC-SHA256 · SHA-256                                      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Crates de Rust Auditadas                                    │
│  curve25519-dalek · ed25519-dalek · RustCrypto              │
└─────────────────────────────────────────────────────────────┘
```

### Estructura de Directorios

```
signalis/
├── 📁 src/
│   ├── index.ts             ← Superficie pública de la API
│   ├── constants.ts         ← Tamaños, info strings, validadores
│   ├── crypto.ts            ← Wrappers sobre signalis-core
│   ├── errors.ts            ← Jerarquía tipada de errores
│   ├── types.ts             ← Tipos branded + type guards
│   └── 📁 identity/
│       ├── index.ts
│       └── identity-key.ts  ← IdentityKeyPair + PublicIdentityKey
│
├── 📁 __tests__/            ← Suite de tests con Vitest
├── 📁 .github/
│   ├── workflows/
│   │   ├── ci.yml           ← Lint + test en PR
│   │   └── release.yml      ← Auto-publicar en tag
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
│
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── vitest.config.ts
├── README.md                ← Versión en inglés
├── README.es.md             ← Este archivo
├── CHANGELOG.md
├── MIGRATION.md
├── ROADMAP.md
├── API.md
├── EXAMPLES.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── LICENSE
└── NOTICE
```

---

## 🔒 Seguridad

### Principios de Diseño

1. **Solo primitivas auditadas** — Toda la criptografía viene de `@brashkie/signalis-core` (construida sobre `RustCrypto` y `curve25519-dalek`)
2. **Operaciones en tiempo constante** — Para todas las comparaciones y verificaciones (delegadas a la capa Rust)
3. **Higiene de memoria** — Las private keys se zeroizan al destruirse (en la capa Rust)
4. **Type safety** — Los tipos branded previenen mezclar public/private keys en tiempo de compilación
5. **Defaults seguros** — `toString()`, `toJSON()`, y el output de inspect de Node NUNCA filtran private keys
6. **Validación de input** — Cada API pública valida tamaños y tipos

### Reglas Críticas de Seguridad

```
🚨 NUNCA loguees un IdentityKeyPair serializado (contiene la private key)
🚨 NUNCA transmitas un IdentityKeyPair serializado por la red
🚨 NUNCA uses console.log() sobre un IdentityKeyPair sin revisar tus logs
🚨 SIEMPRE guarda identity keys en storage encriptado (KMS, keychain, etc.)
🚨 SIEMPRE verifica fingerprints fuera de banda antes de confiar en public keys
🚨 NUNCA reutilices un par (key, nonce) en AES-GCM
🚨 NUNCA uses secretos compartidos de ECDH directamente — siempre deriva con HKDF
```

### Qué es SEGURO

```typescript
const alice = IdentityKeyPair.generate();

// ✅ SEGURO — NO incluye la private key
console.log(alice);                  // "IdentityKeyPair(public=a1b2c3...)"
console.log(JSON.stringify(alice));  // {"type":"IdentityKeyPair","publicKey":"..."}
console.log(alice.toString());       // Igual que arriba
```

### Qué es PELIGROSO

```typescript
// ⚠️ PELIGRO — el serialize() explícito incluye la private key
const data = alice.serialize();
console.log(data); // EXPONE LA PRIVATE KEY
```

### Reportar Vulnerabilidades

Por favor lee [SECURITY.md](SECURITY.md) para el proceso de divulgación responsable.

**NO abras issues públicos de GitHub para vulnerabilidades de seguridad.**

---

## 🧪 Testing

### Cobertura de Tests

```
✅ ~100+ tests entre:
   ├── constants.test.ts      → Constantes y validadores
   ├── crypto.test.ts          → Wrappers crypto (incluyendo XEd25519, Ed25519, AAD)
   ├── errors.test.ts          → Jerarquía de errores
   ├── types.test.ts           → Tipos branded y guards
   └── identity-key.test.ts    → IdentityKeyPair + PublicIdentityKey + Firma

✅ Vectores de test:
   ├── Vector 1 de RFC 8032 (Ed25519)
   ├── Vectores SHA-256 del NIST
   └── Tests de round-trip para serialize/deserialize
```

### Correr Tests

```bash
# Correr todos los tests
npm test

# Modo watch
npm run test:watch

# Reporte de coverage
npm run test:coverage

# Coverage UI (interactivo)
npm run test:ui
```

---

## 🔧 Compilar desde Código Fuente

```bash
# Prerequisitos:
#   - Node.js 18+
#   - npm 9+

git clone https://github.com/Brashkie/signalis.git
cd signalis

npm install
npm run build
npm test
```

Los artefactos de build estarán en `dist/`:

- `dist/index.cjs` — Bundle CommonJS
- `dist/index.mjs` — Bundle ESM
- `dist/index.d.ts` — Declaraciones TypeScript
- `dist/index.d.cts` — Tipos específicos de CJS
- `dist/index.d.mts` — Tipos específicos de ESM

---

## 🗺️ Roadmap

Seguimos un enfoque **basado en sprints**. Cada sprint agrega un componente importante del Protocolo Signal.

### ✅ Sprint 1: Fundamentos de Identidad & PreKey (v0.1.0 - v0.2.0)
- ✅ Clase `IdentityKeyPair` con serialización
- ✅ Clase `PublicIdentityKey`
- ✅ Tipos branded (`PublicKey`, `PrivateKey`, `Signature`, ...)
- ✅ Jerarquía tipada de errores
- ✅ Constantes de separación de dominio (info strings de X3DH, etc.)
- ✅ **v0.2.0:** Firma XEd25519 en identity keys
- ✅ **v0.2.0:** Wrappers Ed25519 (signing keys separadas)
- ✅ **v0.2.0:** Soporte AES-GCM con AAD
- ✅ **v0.2.0:** Vectores de test RFC 8032

### 🚧 Sprint 2: PreKeys + X3DH (v0.3.0 — en desarrollo)
- 🚧 Clase `OneTimePreKey`
- 🚧 Clase `SignedPreKey` (firmada con identity via XEd25519)
- 🚧 `PreKeyBundle` (payload server-facing)
- 🚧 Flujo iniciador X3DH (`X3DH.initiate(bobBundle)`)
- 🚧 Flujo respondedor X3DH (`X3DH.receive(initialMsg)`)
- 🚧 4-way DH (DH1, DH2, DH3, DH4)
- 🚧 Derivación de root key + chain key via HKDF

### 🔜 Sprint 3: Double Ratchet (v0.4.0)
- 🔜 Ratchet simétrico
- 🔜 Ratchet DH
- 🔜 Skipped message keys (entrega fuera de orden)
- 🔜 Forward + backward secrecy completos
- 🔜 Clase Session con `encrypt(msg)` / `decrypt(packet)`

### 🔜 Sprint 4: Capa de Storage (v0.5.0)
- 🔜 Interfaz `SessionStore`
- 🔜 `PreKeyStore`, `SignedPreKeyStore`, `IdentityStore`
- 🔜 Implementación en memoria (para tests)
- 🔜 Adapter SQLite (referencia)
- 🔜 Patrón "bring-your-own-storage"

### 🔜 Sprint 5: Mensajería Grupal (v0.6.0)
- 🔜 Sender Keys
- 🔜 Gestión de sesiones de grupo
- 🔜 Cifrado eficiente multi-destinatario

### 🔜 Objetivos v1.0.0
- ✅ Superficie de API estable
- ✅ Auditoría de seguridad externa
- ✅ Sitio de documentación completo
- ✅ Implementaciones de referencia (app de chat, IoT)
- ✅ Benchmarks de performance

Ver [ROADMAP.md](ROADMAP.md) para planes detallados.

---

## 🔗 Ecosistema

El stack crypto/messaging de Hepein:

```
┌─────────────────────────────────────────────┐
│  HepeinBaileys 2.0 (Futuro)                 │  ← Cliente WhatsApp completo
│  Cliente WhatsApp completo desde cero       │     (reemplaza Baileys)
├─────────────────────────────────────────────┤
│  @brashkie/waproto (Futuro)                 │  ← Protocolo WhatsApp wire
│  Compatibilidad wire-format con WhatsApp    │
├─────────────────────────────────────────────┤
│  @brashkie/signalis ← ESTÁS AQUÍ            │  ← Lógica del Protocolo Signal
│  X3DH · Double Ratchet · Sender Keys        │
├─────────────────────────────────────────────┤
│  @brashkie/signalis-core (v0.2.0 ✅)        │  ← Primitivas crypto
│  Curve25519 · Ed25519 · HKDF · AES-GCM      │
├─────────────────────────────────────────────┤
│  Rust auditado (curve25519-dalek, etc.)     │  ← Crypto battle-tested
└─────────────────────────────────────────────┘
```

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Por favor lee [CONTRIBUTING.md](CONTRIBUTING.md) para las pautas.

Para nuevas features o cambios disruptivos, abre primero un issue para discutir.

### Flujo de Desarrollo

```bash
# Clonar e instalar
git clone https://github.com/Brashkie/signalis.git
cd signalis
npm install

# Hacer cambios...

# Verificar
npm run lint
npm run typecheck
npm test
npm run build

# Commit (seguimos Conventional Commits)
git commit -m "feat(identity): agregar nueva feature"
```

---

## 📜 Licencia

Apache License 2.0 — ver [LICENSE](LICENSE) para detalles.

Las licencias de terceros están listadas en [NOTICE](NOTICE).

---

## 🙏 Agradecimientos

Construido sobre los hombros de gigantes:

- **[@brashkie/signalis-core](https://www.npmjs.com/package/@brashkie/signalis-core)** — Primitivas crypto (Curve25519, Ed25519, XEd25519, HKDF, AES-GCM, ...)
- **[Signal Foundation](https://signal.org/)** — Especificaciones del protocolo ([X3DH](https://signal.org/docs/specifications/x3dh/), [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/), [XEdDSA](https://signal.org/docs/specifications/xeddsa/))
- **[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)** — Curve25519 en Rust puro
- **[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)** — Ed25519 en Rust puro
- **[RustCrypto](https://github.com/RustCrypto)** — `aes`, `hkdf`, `hmac`, `sha2`
- **[tsup](https://tsup.egoist.dev/)** — Bundler dual ESM/CJS
- **[Vitest](https://vitest.dev/)** — Test runner moderno

---

<div align="center">

🔐 + ❤️ por [Hepein Oficial](https://github.com/Brashkie)

[Reportar Bug](https://github.com/Brashkie/signalis/issues) · [Pedir Feature](https://github.com/Brashkie/signalis/issues) · [Documentación](https://github.com/Brashkie/signalis#readme)

</div>