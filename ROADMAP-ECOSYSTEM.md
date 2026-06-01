# Signalis Ecosystem Roadmap

> **Visión de largo plazo del stack `@brashkie/signalis-*`**
>
> Este documento es **aspiracional**, no un compromiso. Su propósito es:
> 1. No perder ideas mientras estamos enfocados en `signalis@1.0`
> 2. Dar contexto a futuros contribuidores sobre la dirección
> 3. Validar decisiones de arquitectura del package principal contra el plan a largo plazo
>
> **Reglas del juego:**
> - 🚫 **NO** se trabaja en ningún package nuevo hasta que `signalis@1.0` esté publicado
> - ✅ Cada package debe justificar su existencia con un problema real
> - ✅ Cada package se hace ÚNICAMENTE si tenemos capacidad de mantenerlo

---

## 📑 Estado Actual

```
@brashkie/signalis-core    ✅ v0.2.0 publicado
@brashkie/signalis         ✅ v0.3.0 publicado (Identity + PreKeys)
                           🚧 v0.4.0 en desarrollo (X3DH)
```

---

## 🗺️ Fases del Ecosistema

### Fase 0 — Foco Actual (en curso)

**Objetivo:** Llegar a `@brashkie/signalis@1.0`

```
v0.4.0 → X3DH (Sprint 2 Part 2)
v0.5.0 → Double Ratchet (Sprint 3)
v0.6.0 → Storage interfaces (Sprint 4)
v0.7.0 → Sender Keys / grupos (Sprint 5)
v0.8.0 → API polish + benchmarks
v0.9.0 → Release candidate + audit externo
v1.0.0 → Production-ready 🎉
```

**Timeline estimado:** 6-12 meses

---

### Fase 1 — Expansión Inmediata (post-v1.0)

Estos 4 packages cubren brechas reales en el ecosistema JS y son **dependencias naturales** del trabajo en HepeinBaileys / waproto.

#### 1️⃣ `@brashkie/signalis-storage`
**Por qué:** Toda app necesita persistir sesiones/llaves. `signalis@1.0` solo define interfaces.

**Contenido:**
- `InMemoryStore` (para tests)
- `SQLiteStore` (referencia)
- `PostgresStore`
- `RedisStore`
- `IndexedDBStore` (browser)
- Migración entre stores

#### 2️⃣ `@brashkie/signalis-vault`
**Por qué:** Manejo seguro de claves al-disco es una brecha REAL en JS. Nadie lo hace bien.

**Contenido:**
- Encrypted key storage (password-based)
- OS keychain integration (Windows DPAPI, macOS Keychain, Linux libsecret)
- Hardware token support (YubiKey) — opcional
- Key rotation helpers
- Backup/restore con verificación

#### 3️⃣ `@brashkie/signalis-codec`
**Por qué:** WhatsApp usa Protobuf. waproto lo va a necesitar.

**Contenido:**
- Protobuf 3 encoding/decoding (binding a `protobufjs` o nativo)
- MessagePack (binding a `msgpackr`)
- Custom binary wire format helpers
- Type-safe deserialization con validación de schemas

#### 4️⃣ `@brashkie/signalis-cli`
**Por qué:** Una vez tengas 3+ packages, DX se vuelve dolorosa sin CLI.

**Contenido:**
- `signalis keygen` — genera identidad
- `signalis prekeys generate --count 100`
- `signalis bundle inspect <payload>`
- `signalis bench` — benchmarks rápidos
- `signalis debug session <file>`

---

### Fase 2 — Networking & Protocols Alternativos

Solo si hay demanda real o un producto interno (HepeinBaileys 2.0) lo necesita.

#### 5️⃣ `@brashkie/signalis-noise`
**Por qué:** Noise Protocol es el futuro de protocolos cifrados (WhatsApp, WireGuard, Tailscale).

**Contenido:**
- Patterns XX, IK, XK, NK
- Noise framing
- Integración con `signalis-core` para primitivas

#### 6️⃣ `@brashkie/signalis-wasm`
**Por qué:** `signalis-core` es Node-only. Necesitamos browser.

**Contenido:**
- Build WASM de `signalis-core`
- Mismo API que la versión nativa
- Bundle size optimizado (< 200 KB)
- Polyfill de `Buffer` para browser

#### 7️⃣ `@brashkie/signalis-net`
**Por qué:** Abstracción común sobre WS/TCP/QUIC con backpressure y reconexión.

**Contenido:**
- `Transport` interface unificado
- WebSocket adapter
- TCP adapter (Node)
- QUIC adapter (vía `node:net` futuro o externo)
- Auto-reconnect, heartbeat, backpressure

---

### Fase 3 — Seguridad Avanzada

#### 8️⃣ `@brashkie/signalis-token`
**Por qué:** Firma de tokens (JWT/PASETO) con identity keys. ÚTIL, no auth completo.

**Contenido:**
- PASETO v4 (recomendado, usa Ed25519)
- JWT firma con Ed25519
- **NO** incluye OAuth — solo helpers de firma/verificación

#### 9️⃣ `@brashkie/signalis-shield`
**Por qué:** Rate limit + anti-spam + anti-tamper para protocolos.

**Contenido:**
- Token bucket rate limiter
- Sliding window rate limiter
- Proof-of-work challenges (anti-spam para handshakes)
- Replay attack detection
- Time-based rejection (clock skew tolerance)

---

### Fase 4 — Tooling Avanzado

#### 🔟 `@brashkie/signalis-devtools`
- Tracing de sesiones (console + browser extension)
- Crypto inspector (hex dump + decode)
- Session inspector

#### 1️⃣1️⃣ `@brashkie/signalis-bench`
- Benchmarks comparativos (vs libsignal-node, vs libsodium)
- Stress tests con resultados publicables
- Memory profiling

#### 1️⃣2️⃣ `@brashkie/signalis-telemetry`
- Adapter OpenTelemetry para `signalis-*`
- Métricas estándar (handshakes/sec, messages/sec, etc.)
- Traces de protocolo

---

### Fase 5 — Investigación / Futuro Lejano

#### 1️⃣3️⃣ `@brashkie/signalis-p2p`
**Por qué:** libp2p existe pero es heavy. Algo lean para WhatsApp-like apps.

**Cuándo:** Solo si HepeinBaileys 2.0 lo necesita en P2P directo.

#### 1️⃣4️⃣ `@brashkie/signalis-relay`
**Por qué:** Forwarding distribuido para metadata privacy.

**Cuándo:** Después de p2p, si hay demanda.

#### 1️⃣5️⃣ `@brashkie/signalis-mls`
**Por qué:** Messaging Layer Security (RFC 9420) es el sucesor oficial del Signal Protocol para grupos grandes.

**Cuándo:** Cuando MLS esté maduro en producción (varios años).

#### 1️⃣6️⃣ `@brashkie/signalis-quantum`
**Por qué:** Post-quantum crypto.

**Cuándo:** Cuando NIST finalice estándares (Kyber/Dilithium ya casi listos, pero no battle-tested en JS).

---

## ❌ Lo Que NO Se Va a Hacer

Para evitar scope creep, estos NO son objetivos del ecosistema:

| Idea | Por qué NO |
|------|-----------|
| `signalis-tls` | TLS es enorme (50k+ líneas). Usar `rustls` directamente. |
| `signalis-simd` | Optimización interna de `signalis-core`, NO package separado. RustCrypto ya lo hace. |
| `signalis-runtime` | `tokio` + `napi-rs` ya lo cubren. No reinventar runtimes. |
| `signalis-cluster` | Application-layer. Reemplazado por `signalis-storage` con adapters distribuidos. |
| `signalis-auth` (OAuth) | Dominio enorme y orthogonal. Usar Auth0/openid-client. Solo exponemos `signalis-token`. |
| `signalis-ai` | Product-specific (va en HepeinBaileys, no en `@brashkie/*`). |

---

## 🏗️ Cuando Llegue el Momento — Estructura Monorepo

Cuando `signalis@1.0` esté publicado y empecemos Fase 1, migrar a monorepo:

```
hepein-stack/                       ← un solo repo en GitHub
├── packages/
│   ├── signalis-core/              ← @brashkie/signalis-core
│   ├── signalis/                   ← @brashkie/signalis
│   ├── signalis-storage/           ← @brashkie/signalis-storage
│   ├── signalis-vault/             ← @brashkie/signalis-vault
│   └── ...
├── apps/
│   └── examples/                   ← demos integrados
├── pnpm-workspace.yaml             ← pnpm workspaces
├── turbo.json                      ← Turbo build cache
└── .changeset/                     ← changesets para versionar
```

**Ventajas:**
- Un solo `pnpm install` desarrolla todo
- Tests cruzados automáticos en CI
- Cambio breaking en `signalis-core` rompe `signalis` inmediatamente (lo cachas)
- Versionado coordinado con [changesets](https://github.com/changesets/changesets)

**Cuándo migrar:** Cuando empecemos el 3er package (`signalis-storage` o el que sea).

---

## 🎯 Criterios Para Empezar Un Package Nuevo

Antes de iniciar cualquier package nuevo, debe cumplir TODOS:

- [ ] `signalis@1.0` ya está publicado y estable
- [ ] El package resuelve un problema CONCRETO que hemos encontrado nosotros
- [ ] Tenemos capacidad de mantenerlo (CI/CD, releases, issues, security patches)
- [ ] El alcance está bien definido y NO es "una librería que hace TODO X"
- [ ] Existe al menos 1 caso de uso interno o publicado que lo justifique

Si fallás cualquiera de estos, el package se queda en este roadmap, no se empieza.

---

## 📝 Cambio Histórico

| Fecha | Cambio |
|-------|--------|
| 2026-05-27 | Documento inicial. Visión completa del ecosistema. |

---

🔐 + ❤️ [Hepein Oficial](https://github.com/Brashkie)
