# 🩹 Signalis v0.7.0 — Fix Bundle (ESLint + README.es.md)

## 🎯 Lo Que Trae

### 🐛 Fix 1: ESLint `no-control-regex` en `src/address.ts`

**Error:**
```
src/address.ts
  30:33  error  Unexpected control character(s) in regular expression: \x00, \x1f
                no-control-regex
```

**Por qué pasó:**
El regex en `FORBIDDEN_USER_ID_CHARS` usa `\x00-\x1f` **a propósito** —
queremos rechazar control chars en userIds (protección contra inyección,
path traversal, etc.). Pero ESLint marca cualquier control char en regex
porque normalmente es un bug accidental.

**Solución:**
Agregar comentario `eslint-disable-next-line no-control-regex` específico
de esa línea, con explicación de por qué es intencional. Esto es la
solución canónica — no apagamos el rule globalmente porque queremos que
detecte casos accidentales en otros archivos.

### 🌎 Fix 2: `README.es.md` actualizado a v0.7.0

El README español estaba en la sección "Novedades v0.4.0" (nunca se
actualizó cuando salieron v0.5 ni v0.6). Lo reemplazo con la versión
v0.7.0 traducida del README inglés actual:

- Badge de tests: `395 passing` → `745 passing`
- Sección "Novedades en v0.7.0" agregada
- Ejemplo de código del Storage Layer en español
- Lista de features automáticas (TOFU, replay protection, etc.)

## 📦 Contenido

```
src/address.ts       ← Fix ESLint (línea 30 con eslint-disable comment)
README.es.md         ← Sección Novedades v0.7.0 al inicio
```

## 🚀 Aplicar

```powershell
cd F:\Brashkie\PROYECTOS\NPM\signalis

# Extraer el ZIP (sobrescribe los 2 archivos)

# Verificar el fix de ESLint
npm run lint
# Esperado: 0 errors, 0 warnings ✅

# Verificar el README español (preview en VS Code)
code README.es.md
# Ctrl+Shift+V → markdown preview
```

## 🚀 Después

Una vez verde el lint, seguís con el plan original:

```powershell
npx tsc --noEmit
npm test              # ~745 tests passing
npm run test:coverage # 100%

git add .
git commit -m "feat(v0.7.0): Sprint 4 — Storage Layer

[mensaje completo del README INSTRUCTIONS-v0.7.0.md]"
git push origin main

# Tras CI verde:
git tag v0.7.0
git push origin v0.7.0
```

---

🔐 + ❤️ Hepein Oficial
