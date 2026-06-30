# 🚀 Signalis v0.7.0 — Storage Layer

## 🎯 Lo Que Trae

**v0.7.0 es la versión que separa "librería Signal Protocol" de "fundación para una app de mensajería real".** Antes los devs tenían que armar persistencia a mano; ahora hay un sistema canónico de 4 stores + facade + high-level API.

```
✅ ProtocolAddress class (multi-device, filesystem-safe)
✅ 4 store interfaces (Identity/PreKey/SignedPreKey/Session)
✅ Memory stores (4 impls) — para tests
✅ File stores (4 impls) — atomic writes, owner-only chmod
✅ StoreBundle facade
✅ SessionBuilder high-level API
✅ ~90 tests nuevos
✅ 100% backward compatible con v0.6.0
✅ Zero deps externas (solo node:fs + node:crypto + node:path)
```

## 📦 What's In

```
src/
├── address.ts                          ← NUEVO (147 líneas)
├── constants.ts                        ← VERSION bumped a "0.7.0"
├── index.ts                            ← exports storage + ProtocolAddress
└── storage/                            ← TODO NUEVO
    ├── index.ts                        — barrel
    ├── types.ts                        — 4 interfaces
    ├── bundle.ts                       — StoreBundle facade
    ├── session-builder.ts              — high-level API
    ├── memory/
    │   ├── index.ts
    │   ├── identity-store.ts
    │   ├── prekey-store.ts
    │   ├── signed-prekey-store.ts
    │   └── session-store.ts
    └── file/
        ├── index.ts
        ├── atomic-write.ts             — write-tmp + fsync + rename
        ├── identity-store.ts
        ├── prekey-store.ts
        ├── signed-prekey-store.ts
        └── session-store.ts

__tests__/                              ← 6 archivos NUEVOS
├── address.test.ts                     (~25 tests)
├── memory-stores.test.ts               (~30 tests)
├── file-stores.test.ts                 (~20 tests)
├── store-bundle.test.ts                (~10 tests)
├── session-builder.test.ts             (~15 tests)
└── storage-e2e.test.ts                 (~5 tests)

examples/
└── 08-storage-layer.ts                 ← NUEVO demo end-to-end

CHANGELOG.md                            ← entry v0.7.0
README.md                               ← What's New v0.7.0 + badge 745 tests
package.json                            ← version 0.7.0
```

## 🚀 Aplicar

```powershell
cd F:\Brashkie\PROYECTOS\NPM\signalis

# IMPORTANTE: hacé un backup primero, esto sobrescribe muchos archivos
git stash  # o git commit lo que tengas pendiente

# Extraer signalis-v0.7.0.zip en la raíz del repo
# (sobrescribe src/, __tests__/, package.json, CHANGELOG.md, README.md)
# Y AGREGA src/address.ts, src/storage/*, __tests__/address.test.ts, etc.

# Verificar que el bump quedó bien
Select-String -Path package.json -Pattern '"version"' | Select-Object -First 1
Select-String -Path src/constants.ts -Pattern "VERSION =" | Select-Object -First 1
```

## ✅ Validar localmente

```powershell
# Instalar (no debe haber nuevas deps)
npm install

# Lint
npm run lint

# Type check
npx tsc --noEmit

# Tests
npm test

# Coverage (debe seguir ~100%)
npm run test:coverage

# Probar el example nuevo
npx tsx examples/08-storage-layer.ts
```

**Esperado de `npm test`:**
- ~745 tests passing (655 v0.6.0 + ~90 nuevos)
- 0 failing

**Esperado del example:**
- Demo corre completo
- Imprime fingerprints de Alice y Bob
- Conversación 5x ping-pong
- "App restart" funciona
- Imprime el árbol de archivos en `~/.signalis/<alice>` (con identity.json, prekeys/, sessions/, etc.)

## 🚀 Commit + Tag

```powershell
git add .
git commit -m "feat(v0.7.0): Sprint 4 — Storage Layer

Ships the persistence layer + high-level API that turns signalis from
a 'Signal Protocol spec library' into a 'fundación for real messaging apps'.

NEW:
- ProtocolAddress class (multi-device peer identifier)
- 4 store interfaces (IdentityStore, PreKeyStore, SignedPreKeyStore, SessionStore)
- Memory implementations (4 stores) — for tests + ephemeral apps
- File implementations (4 stores) — atomic writes, owner-only chmod, JSON
- StoreBundle facade — combines 4 stores into one
- SessionBuilder high-level API — auto X3DH bootstrap + TOFU + replay protection
- ~90 new tests (~745 total)

CHANGED:
- VERSION 0.6.0 → 0.7.0
- src/index.ts exports new storage module

UNCHANGED:
- 100% backwards compatible with v0.6.0
- Zero new dependencies (only node:fs + node:crypto + node:path)
- All existing APIs (Session.initiateFromX3DH, session.encrypt) work identically"

# Push SIN tag primero, esperar CI verde
git push origin main

# Una vez CI verde:
git tag v0.7.0
git push origin v0.7.0
```

## 📋 Roadmap Restante

```
✅ v0.7.0 — Storage Layer + SessionBuilder         ← AQUÍ
🔜 v0.8.0 — Sender Keys (group messaging)
🔜 v0.9.0 — Browser/IndexedDB store (paquete @brashkie/signalis-browser)
🎯 v1.0.0 — Production-ready + audit externa
```

## 💡 Notas Sobre El Diseño

### ¿Por qué 4 interfaces separadas?

Signal canonical lo hace así. Permite que un dev plugee SQLite para
identity+prekeys pero Redis para sessions (que rotan más rápido). Si las
hubieras juntado, no se puede.

### ¿Por qué async/await en todo?

Memory store no necesita async técnicamente, pero si la interface
quedara síncrona, después no podés enchufar SQLite/IndexedDB/Redis sin
romper backwards compat. Así de fácil. El costo de `Promise.resolve(x)`
en Memory es despreciable.

### ¿Por qué atomic writes en File store?

Sin atomic writes, si el proceso crashea **mientras escribís `session.json`**,
el archivo queda truncado → la session queda **corrompida** → Bob no puede
desencriptar lo que Alice le manda → app rota. Atomic writes garantizan que
en cualquier momento el archivo en disco es OLD o NEW, nunca middle.

### ¿Por qué chmod 600 en identity.json?

Es la KEY PRIVADA del user. Si otra cuenta UNIX del mismo sistema puede
leerla, MITM total. `chmod 600` la deja solo readable por el owner.

### ¿Por qué consume + delete del one-time prekey?

Signal one-shot semantics. Si reusás el mismo prekey, **rompe forward
secrecy**. Por eso el SessionBuilder lo borra automáticamente después del
primer decrypt. Si reciben el mismo packet 2 veces (replay attack), el
segundo intento falla porque el prekey ya no está.

## 🎯 Qué Hace Que Esto Sea v0.7 y No v1.0?

Lo que falta para v1.0:
1. **Sender Keys** (group messaging) — v0.8.0
2. **Browser store** (IndexedDB) — v0.9.0
3. **External security audit** — v1.0.0

Pero ya con v0.7.0 podés armar:
- ✅ Apps Node.js de mensajería 1-on-1 (CLIs, Electron, Termux)
- ✅ Bots de WhatsApp/Telegram con E2E real (no el del fabricante)
- ✅ Apps Mobile (React Native con `react-native-fs` como adaptador del file store)

---

🔐 + ❤️ Hepein Oficial
Build with passion. Ship with care. — Brashkie
