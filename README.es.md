<div align="center">

<img src="media/logo.png" alt="Signalis" width="180" />

# @brashkie/signalis

**Implementación del Protocolo Signal en TypeScript, lista para producción.**
**X3DH · Double Ratchet · Sender Keys · Gestión de Identidad.**

[![npm version](https://img.shields.io/npm/v/@brashkie/signalis.svg?style=flat-square&color=cb3837)](https://www.npmjs.com/package/@brashkie/signalis)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](LICENSE)
[![Node.js Version](https://img.shields.io/node/v/@brashkie/signalis.svg?style=flat-square&color=339933)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-6.0-3178c6.svg?style=flat-square)](https://www.typescriptlang.org)
[![Tests](https://img.shields.io/badge/tests-395%20passing-success.svg?style=flat-square)](#-testing)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg?style=flat-square)](#-testing)
[![CI](https://img.shields.io/github/actions/workflow/status/Brashkie/signalis/ci.yml?style=flat-square&label=CI)](https://github.com/Brashkie/signalis/actions/workflows/ci.yml)
[![Powered by Rust](https://img.shields.io/badge/powered_by-Rust-orange.svg?style=flat-square)](https://www.rust-lang.org)

[English](README.md) · [**Español**](README.es.md)

Hecho con 🔐 + ❤️ por [Hepein Oficial](https://github.com/Brashkie)

</div>

---

## 📑 Tabla de Contenidos

- [¿Qué es Signalis?](#-qué-es-signalis)
- [Novedades en v0.3.0](#-novedades-en-v030)
- [Características](#-características)
- [¿Por qué Signalis?](#-por-qué-signalis)
- [Instalación](#-instalación)
- [Inicio Rápido en 5 Minutos](#-inicio-rápido-en-5-minutos)
- [Ejemplos Completos](#-ejemplos-completos)
- [Resumen de la API](#-resumen-de-la-api)
- [Arquitectura](#-arquitectura)
- [Seguridad](#-seguridad)
- [Testing](#-testing)
- [Comparación con Alternativas](#-comparación-con-alternativas)
- [Roadmap](#-roadmap)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)

---

## ✨ ¿Qué es Signalis?

`@brashkie/signalis` es una **implementación en TypeScript del Protocolo Signal** — el mismo protocolo de cifrado extremo a extremo que usan Signal, WhatsApp y Skype. Provee:

- 🔑 **Identity Keys** — Gestión de identidad de largo plazo con firma XEd25519
- 🔁 **PreKey Bundles** — Establecimiento asíncrono de sesiones (X3DH)
- 🪜 **Double Ratchet** — Forward y backward secrecy para cada mensaje *(Sprint 3)*
- 👥 **Sender Keys** — Mensajería grupal eficiente *(Sprint 5)*
- 💾 **Capa de Storage** — Persistencia pluggable para sesiones/llaves *(Sprint 4)*
- 🛡️ **Construido sobre `@brashkie/signalis-core`** — Primitivas criptográficas en Rust nativo

> **Parte del ecosistema [Hepein](https://github.com/Brashkie).**
> Base para `@brashkie/waproto` (Protocolo WhatsApp) y eventualmente una alternativa a Baileys construida desde cero.

---

## 🎉 Novedades en v0.3.0

**v0.3.0 trae la capa de PreKeys — la base para X3DH.** Bob puede publicar un `PreKeyBundle` con prekeys firmados con su identity, y Alice puede descargarlo y **verificarlo automáticamente** antes de iniciar una sesión.

### 🆕 Clases Nuevas

| Clase | Propósito |
|-------|-----------|
| `OneTimePreKey` | Keypairs Curve25519 efímeros de uso único |
| `SignedPreKey` | Keypair de mediano plazo firmado con identity (XEd25519) — rotado semanalmente |
| `PreKeyBundle` | Payload completo server-facing para X3DH |
| `PublicOneTimePreKey` | Forma pública (subida al servidor) |
| `PublicSignedPreKey` | Forma pública verificada para bundles recibidos |

### 🛡️ Seguridad Incluida

- ✅ Signed prekeys verificados automáticamente en `fromPayload()` (lanza `SignatureError` si hay tampering)
- ✅ Helpers de ciclo de vida (`needsRotation()`, `isExpired()`, `ageMs()`)
- ✅ Prevención de forja de Mallory testeada con tests explícitos
- ✅ Validación estricta de inputs (tamaños de llaves, IDs, formato hex, rangos de registration)

### 📊 Métricas de Calidad

```
✅ 395 tests pasando
✅ 100% statements
✅ 100% branches
✅ 100% functions
✅ 100% lines
```

**100% compatible hacia atrás** con v0.2.0.

---

## 🚀 Características

| Característica | Estado | Sprint |
|----------------|--------|--------|
| 🔑 **Identity Key Pair** (Curve25519) | ✅ | 1 |
| ✍️ **Firma XEd25519 en identity keys** | ✅ | 1.2 |
| 🛡️ **Tipos branded** (PublicKey vs PrivateKey en tiempo de compilación) | ✅ | 1 |
| 🎯 **Type-safe** con soporte TypeScript 6.0 completo | ✅ | 1 |
| 📦 **Paquete dual ESM/CJS** | ✅ | 1 |
| 🧪 **100% cobertura de tests** con vectores RFC | ✅ | 2.1 |
| 🔐 **Defaults seguros** (no fuga de private keys en toString) | ✅ | 1 |
| 💾 **Serialización/deserialización** (compatible con JSON) | ✅ | 1 |
| 🔁 **One-Time PreKeys** | ✅ NUEVO | 2.1 |
| ✍️ **Signed PreKeys** (firmados con identity via XEd25519) | ✅ NUEVO | 2.1 |
| 📦 **PreKey Bundles** (payload server-facing para X3DH) | ✅ NUEVO | 2.1 |
| 🤝 **X3DH** (Extended Triple Diffie-Hellman) | 🚧 | 2.2 |
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
| **Cobertura de Tests** | ✅ **100%** | 🟡 Desconocida | ❌ Desconocida |
| **Mantenimiento activo** | ✅ Activo | 🟡 Esporádico | ❌ Stale |
| **Dual ESM/CJS** | ✅ | ❌ | ❌ |
| **API moderna** | ✅ Basada en clases, async-friendly | 🟡 Estilo viejo | 🟡 Con muchos callbacks |
| **Licencia** | Apache-2.0 | GPL-3.0 | GPL-3.0 |

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

## ⚡ Inicio Rápido en 5 Minutos

¿Quieres ver Signalis funcionando en 5 minutos? Copia y pega esto:

### `quickstart.ts`

```typescript
import {
  IdentityKeyPair,
  PublicIdentityKey,
  SignedPreKey,
  OneTimePreKey,
  PreKeyBundle,
} from '@brashkie/signalis';

// ════════════════════════════════════════════════════════════════════════
// PARTE 1: Identidad y Firmas (✅ Disponible en v0.2.0+)
// ════════════════════════════════════════════════════════════════════════

console.log('\n🔑 PARTE 1 — Identidad y Firmas\n');

// Generar la identidad de largo plazo de Alice (una vez al registrar)
const alice = IdentityKeyPair.generate();
console.log('Fingerprint de Alice:', alice.shortFingerprint());

// Alice firma un mensaje
const mensaje = Buffer.from('Yo autorizo esta transacción');
const firma = alice.sign(mensaje);
console.log('Tamaño de firma:', firma.length, 'bytes');

// Bob verifica usando solo la public key de Alice
const alicePub = alice.toPublic();
const alicePublicHex = alicePub.toHex(); // se comparte por la red

// Del lado de Bob:
const aliceKeyRecibida = PublicIdentityKey.fromHex(alicePublicHex);
const esValida = aliceKeyRecibida.verifyBool(mensaje, firma);
console.log('¿Firma válida?', esValida); // → true ✅

// Mallory intenta falsificar:
const mallory = IdentityKeyPair.generate();
const firmaFalsa = mallory.sign(mensaje);
const falsaValida = aliceKeyRecibida.verifyBool(mensaje, firmaFalsa);
console.log('¿Forja de Mallory aceptada?', falsaValida); // → false ✅

// ════════════════════════════════════════════════════════════════════════
// PARTE 2: Setup del PreKey Bundle (✅ Disponible en v0.3.0+)
// ════════════════════════════════════════════════════════════════════════

console.log('\n📦 PARTE 2 — Setup del PreKey Bundle\n');

// Bob publica su prekey bundle al servidor
const bob = IdentityKeyPair.generate();
const bobSpk = SignedPreKey.generate(bob, 1);  // firmado con la identity de bob
const bobOtpks = OneTimePreKey.generateBatch(1, 100); // 100 llaves de uso único

console.log('Fingerprint de Bob:', bob.shortFingerprint());
console.log('Bob SPK ID:', bobSpk.id);
console.log('¿Firma del SPK de Bob verifica?', bobSpk.verify(bob.toPublic())); // → true ✅
console.log('Generadas', bobOtpks.length, 'one-time prekeys');

// El servidor elige la primera prekey de uso único para la solicitud de Alice
const otpkSeleccionada = bobOtpks[0];

const bundleParaAlice = PreKeyBundle.build({
  registrationId: 12345,
  deviceId: 1,
  identityKey: bob.toPublic(),
  signedPreKey: bobSpk.toPublic(),
  oneTimePreKey: otpkSeleccionada.toPublic(),
});

// El servidor guarda esto como JSON
const payloadServidor = bundleParaAlice.toPayload();
console.log('Dirección del bundle:', bundleParaAlice.address());

// ════════════════════════════════════════════════════════════════════════
// PARTE 3: Alice Recibe y Verifica el Bundle de Bob
// ════════════════════════════════════════════════════════════════════════

console.log('\n🔍 PARTE 3 — Alice Verifica el Bundle de Bob\n');

// Alice descarga el bundle de Bob del servidor (ej: HTTPS GET /bundles/bob)
// fromPayload() AUTOMÁTICAMENTE verifica la firma del signed prekey.
// Si alguien alteró o forjó algo, lanza SignatureError.
const bundleVerificado = PreKeyBundle.fromPayload(payloadServidor);

console.log('Bundle verificado ✅');
console.log('  Identidad de Bob:', bundleVerificado.identityKey.shortFingerprint());
console.log('  SPK id de Bob:', bundleVerificado.signedPreKey.id);
console.log('  OTPK id de Bob:', bundleVerificado.oneTimePreKey?.id);
console.log('  ¿Tiene OTPK?', bundleVerificado.hasOneTimePreKey());

// ════════════════════════════════════════════════════════════════════════
// PARTE 4: Detección de Tampering
// ════════════════════════════════════════════════════════════════════════

console.log('\n🛡️ PARTE 4 — El Tampering Es Detectado\n');

// ¿Qué pasa si un servidor malicioso intenta cambiar la identidad de Bob?
const malicioso = IdentityKeyPair.generate();
const bundleMalicioso = {
  ...payloadServidor,
  identityKey: malicioso.toPublic().toHex(), // ← el atacante sustituye su llave
};

try {
  PreKeyBundle.fromPayload(bundleMalicioso);
  console.log('⚠️ Esto NUNCA debería imprimirse');
} catch (e) {
  console.log('Bundle alterado rechazado ✅');
  console.log('Error:', (e as Error).message);
}

console.log('\n🎉 ¡Inicio Rápido Completo!\n');
```

### Ejecutarlo

```bash
# 1. Instalar
npm install @brashkie/signalis

# 2. Guardar el código de arriba como quickstart.ts

# 3. Ejecutar con tsx (o compilar con tsc)
npx tsx quickstart.ts
```

### Output Esperado

```
🔑 PARTE 1 — Identidad y Firmas

Fingerprint de Alice: a1b2c3d4e5f60718
Tamaño de firma: 64 bytes
¿Firma válida? true
¿Forja de Mallory aceptada? false

📦 PARTE 2 — Setup del PreKey Bundle

Fingerprint de Bob: f1e2d3c4b5a60798
Bob SPK ID: 1
¿Firma del SPK de Bob verifica? true
Generadas 100 one-time prekeys

🔍 PARTE 3 — Alice Verifica el Bundle de Bob

Bundle verificado ✅
  Identidad de Bob: f1e2d3c4b5a60798
  SPK id de Bob: 1
  OTPK id de Bob: 1
  ¿Tiene OTPK? true

🛡️ PARTE 4 — El Tampering Es Detectado

Bundle alterado rechazado ✅
Error: SignedPreKey signature verification failed for prekey id 1

🎉 ¡Inicio Rápido Completo!
```

---

## 🧪 Ejemplos Completos

### Ejemplo 1: Persistir la Identidad

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';
import { writeFile, readFile } from 'node:fs/promises';

// Al registrarse (una sola vez)
async function setupIdentidad() {
  const identidad = IdentityKeyPair.generate();
  const data = identidad.serialize();
  // ⚠️ GUARDAR EN STORAGE ENCRIPTADO
  await writeFile('./alice-identity.json', JSON.stringify(data));
  console.log('Identidad creada. Fingerprint:', identidad.shortFingerprint());
}

// Al iniciar la app
async function cargarIdentidad(): Promise<IdentityKeyPair> {
  const raw = await readFile('./alice-identity.json', 'utf-8');
  return IdentityKeyPair.deserialize(JSON.parse(raw));
}
```

### Ejemplo 2: Firmar Requests a la API

```typescript
import { IdentityKeyPair } from '@brashkie/signalis';

const identidad = await cargarIdentidad();

async function fetchFirmado(url: string, options: RequestInit = {}) {
  const timestamp = Date.now().toString();
  const body = options.body?.toString() ?? '';
  
  // Firmar: method + url + timestamp + body
  const aFirmar = Buffer.from(
    `${options.method ?? 'GET'}|${url}|${timestamp}|${body}`,
  );
  const firma = identidad.sign(aFirmar);
  
  return fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'X-Public-Key': identidad.toPublic().toHex(),
      'X-Timestamp': timestamp,
      'X-Signature': firma.toString('base64'),
    },
  });
}
```

### Ejemplo 3: Ciclo de Vida del PreKey Bundle

```typescript
import {
  IdentityKeyPair,
  SignedPreKey,
  OneTimePreKey,
} from '@brashkie/signalis';

class SetupUsuario {
  identidad: IdentityKeyPair;
  signedPreKey: SignedPreKey;
  oneTimePreKeys: OneTimePreKey[];
  
  constructor() {
    this.identidad = IdentityKeyPair.generate();
    this.signedPreKey = SignedPreKey.generate(this.identidad, 1);
    this.oneTimePreKeys = OneTimePreKey.generateBatch(1, 100);
  }
  
  // Ejecutar semanalmente: chequear si el SignedPreKey necesita rotación
  async rotarSiNecesario(serverUrl: string) {
    if (this.signedPreKey.needsRotation()) {
      const nuevoId = this.signedPreKey.id + 1;
      this.signedPreKey = SignedPreKey.generate(this.identidad, nuevoId);
      
      await fetch(`${serverUrl}/keys/signed-prekey`, {
        method: 'POST',
        body: JSON.stringify(this.signedPreKey.toPayload()),
      });
      
      console.log('Signed prekey rotado al id', nuevoId);
    }
  }
}
```

### Ejemplo 4: Recibir y Verificar un Bundle

```typescript
import { PreKeyBundle, SignatureError } from '@brashkie/signalis';

async function obtenerBundleUsuario(userId: string): Promise<PreKeyBundle | null> {
  const response = await fetch(`/api/usuarios/${userId}/bundle`);
  const payload = await response.json();
  
  try {
    // fromPayload AUTOMÁTICAMENTE verifica la firma del signed prekey
    return PreKeyBundle.fromPayload(payload);
  } catch (e) {
    if (e instanceof SignatureError) {
      console.error('SEGURIDAD: ¡Firma del bundle inválida!', e.message);
      // → el servidor puede estar comprometido, NO usar este bundle
    }
    throw e;
  }
}
```

Para más ejemplos, ver [EXAMPLES.md](EXAMPLES.md).

---

## 📚 Resumen de la API

### Módulo Identity

```typescript
class IdentityKeyPair {
  static generate(): IdentityKeyPair;
  static fromKeys(pub: Buffer, priv: Buffer): IdentityKeyPair;
  static deserialize(data: SerializedKeyPair): IdentityKeyPair;
  
  // Firma (XEd25519)
  sign(message: Buffer): Signature;
  signWithRandom(message: Buffer, random: Buffer): Signature;
  verify(message: Buffer, signature: Buffer): void;
  verifyBool(message: Buffer, signature: Buffer): boolean;
  
  // Accesores
  toPublic(): PublicIdentityKey;
  fingerprint(): string;
  shortFingerprint(): string;
  serialize(): SerializedKeyPair;
}

class PublicIdentityKey {
  static fromHex(hex: string): PublicIdentityKey;
  static fromBase64(b64: string): PublicIdentityKey;
  
  verify(message: Buffer, signature: Buffer): void;
  verifyBool(message: Buffer, signature: Buffer): boolean;
  
  toHex(): string;
  toBase64(): string;
  fingerprint(): string;
}
```

### Módulo PreKeys (NUEVO en v0.3.0)

```typescript
class OneTimePreKey {
  static generate(id: number): OneTimePreKey;
  static generateBatch(startId: number, count: number): OneTimePreKey[];
  
  toPublic(): PublicOneTimePreKey;
  serialize(): SerializedOneTimePreKey;
}

class SignedPreKey {
  static generate(identity: IdentityKeyPair, id: number): SignedPreKey;
  
  verify(identityPub: PublicIdentityKey): boolean;
  needsRotation(threshold?: number): boolean;
  isExpired(maxAge?: number): boolean;
  
  toPayload(): PublicSignedPreKeyPayload;
  toPublic(): PublicSignedPreKey;
}

class PreKeyBundle {
  static build(args): PreKeyBundle;
  static fromPayload(payload): PreKeyBundle; // ← auto-verifica firma
  
  hasOneTimePreKey(): boolean;
  address(): string;
  toPayload(): PreKeyBundlePayload;
}
```

Ver [API.md](API.md) para la referencia completa.

---

## 🔒 Seguridad

### Principios de Diseño

1. **Solo primitivas auditadas** — Toda la criptografía viene de `@brashkie/signalis-core`
2. **Operaciones en tiempo constante** — Para todas las comparaciones y verificaciones
3. **Higiene de memoria** — Las private keys se zeroizan al destruirse
4. **Type safety** — Tipos branded previenen mezclar public/private keys
5. **Defaults seguros** — `toString()`, `toJSON()` NUNCA filtran private keys
6. **Validación de input** — Cada API pública valida tamaños y tipos
7. **Verificación automática** — `fromPayload()` verifica firmas por defecto

### Reglas Críticas de Seguridad

```
🚨 NUNCA loguees un IdentityKeyPair / OneTimePreKey / SignedPreKey serializado
🚨 NUNCA transmitas un keypair serializado por la red
🚨 SIEMPRE guarda identity keys en storage encriptado (KMS, keychain, etc.)
🚨 SIEMPRE verifica fingerprints fuera de banda antes de confiar en public keys
🚨 NUNCA reutilices un par (key, nonce) en AES-GCM
🚨 NUNCA uses secretos compartidos de ECDH directamente — siempre deriva con HKDF
🚨 ROTA SignedPreKeys cada 7 días (usa needsRotation())
🚨 NUNCA uses SignedPreKeys expirados para sesiones nuevas
```

### Reportar Vulnerabilidades

Por favor lee [SECURITY.md](SECURITY.md) para el proceso de divulgación responsable.
**NO abras issues públicos de GitHub para vulnerabilidades de seguridad.**

---

## 🧪 Testing

### Cobertura de Tests: 100%

```
✅ 395 tests pasando
✅ 100% statements
✅ 100% branches
✅ 100% functions
✅ 100% lines
```

### Vectores de Test

- ✅ Vector 1 de RFC 8032 (Ed25519)
- ✅ Vectores SHA-256 del NIST
- ✅ Tests de round-trip para todos los serialize/deserialize
- ✅ Tests de prevención de forja de Mallory
- ✅ Escenarios E2E (Alice → servidor → Bob)

### Correr Tests

```bash
npm test                  # Todos los tests
npm run test:watch        # Modo watch
npm test -- --coverage    # Reporte de coverage
npm run test:ui           # UI interactiva
```

---

## 🗺️ Roadmap

### ✅ Sprint 1: Fundamentos de Identidad (v0.1.0 - v0.2.0) — COMPLETO
### ✅ Sprint 2 Parte 1: Capa de PreKeys (v0.3.0) — COMPLETO
### 🚧 Sprint 2 Parte 2: X3DH (v0.4.0) — EN DESARROLLO
### 🔜 Sprint 3: Double Ratchet (v0.5.0)
### 🔜 Sprint 4: Capa de Storage (v0.6.0)
### 🔜 Sprint 5: Mensajería Grupal (v0.7.0)
### 🎯 v1.0.0 — Production-ready con auditoría externa

Ver [ROADMAP.md](ROADMAP.md) para planes detallados y [ROADMAP-ECOSYSTEM.md](ROADMAP-ECOSYSTEM.md) para la visión a largo plazo.

---

## 🔗 Ecosistema

El stack crypto/messaging de Hepein:

```
┌─────────────────────────────────────────────┐
│  HepeinBaileys 2.0 (Futuro)                 │  ← Cliente WhatsApp completo
├─────────────────────────────────────────────┤
│  @brashkie/waproto (Futuro)                 │  ← Protocolo WhatsApp wire
├─────────────────────────────────────────────┤
│  @brashkie/signalis ← ESTÁS AQUÍ (v0.3.0)   │  ← Lógica del Protocolo Signal
├─────────────────────────────────────────────┤
│  @brashkie/signalis-core (v0.2.0 ✅)        │  ← Primitivas crypto
├─────────────────────────────────────────────┤
│  Rust auditado (curve25519-dalek, etc.)     │  ← Crypto battle-tested
└─────────────────────────────────────────────┘
```

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas! Por favor lee [CONTRIBUTING.md](CONTRIBUTING.md) para las pautas.

```bash
git clone https://github.com/Brashkie/signalis.git
cd signalis
npm install
npm test
```

---

## 📜 Licencia

Apache License 2.0 — ver [LICENSE](LICENSE) para detalles.

---

## 🙏 Agradecimientos

Construido sobre los hombros de gigantes:

- **[@brashkie/signalis-core](https://www.npmjs.com/package/@brashkie/signalis-core)** — Primitivas crypto
- **[Signal Foundation](https://signal.org/)** — Especificaciones del protocolo
- **[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)** — Curve25519 en Rust puro
- **[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)** — Ed25519 en Rust puro
- **[RustCrypto](https://github.com/RustCrypto)** — `aes`, `hkdf`, `hmac`, `sha2`
- **[tsup](https://tsup.egoist.dev/)** — Bundler dual ESM/CJS
- **[Vitest](https://vitest.dev/)** — Test runner moderno

---

<div align="center">

<sub>🔐 + ❤️ por [Hepein Oficial](https://github.com/Brashkie)</sub>

[Reportar Bug](https://github.com/Brashkie/signalis/issues) · [Pedir Feature](https://github.com/Brashkie/signalis/issues) · [Documentación](https://github.com/Brashkie/signalis#readme)

</div>
