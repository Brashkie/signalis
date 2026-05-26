# Apply hotfix script for @brashkie/signalis v0.2.0
# Run this in F:\Brashkie\PROYECTOS\NPM\signalis after extracting this hotfix ZIP

Write-Host ""
Write-Host "🔧 @brashkie/signalis v0.2.0 — CI/CD Hotfix" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ─── 1. Replace old configs ──────────────────────────────────────────────
Write-Host "[1/5] Removing old vitest.config.ts (will be replaced by .mts)..." -ForegroundColor Yellow
if (Test-Path "vitest.config.ts") {
    Remove-Item "vitest.config.ts" -Force
    Write-Host "      ✓ Removed vitest.config.ts" -ForegroundColor Green
} else {
    Write-Host "      ℹ vitest.config.ts not found, skipping" -ForegroundColor Gray
}

# ─── 2. Copy new files from hotfix ───────────────────────────────────────
Write-Host "[2/5] Copying new config files from hotfix..." -ForegroundColor Yellow
Copy-Item -Path ".\hotfix\eslint.config.mjs"   -Destination ".\eslint.config.mjs"   -Force
Copy-Item -Path ".\hotfix\vitest.config.mts"   -Destination ".\vitest.config.mts"   -Force
Copy-Item -Path ".\hotfix\package.json"        -Destination ".\package.json"        -Force
Write-Host "      ✓ Copied eslint.config.mjs"   -ForegroundColor Green
Write-Host "      ✓ Copied vitest.config.mts"   -ForegroundColor Green
Write-Host "      ✓ Copied package.json"        -ForegroundColor Green

# ─── 3. Clean and reinstall ──────────────────────────────────────────────
Write-Host "[3/5] Cleaning node_modules and package-lock.json..." -ForegroundColor Yellow
if (Test-Path "node_modules") {
    Remove-Item "node_modules" -Recurse -Force
    Write-Host "      ✓ Removed node_modules/" -ForegroundColor Green
}
if (Test-Path "package-lock.json") {
    Remove-Item "package-lock.json" -Force
    Write-Host "      ✓ Removed package-lock.json" -ForegroundColor Green
}

# ─── 4. Fresh install ────────────────────────────────────────────────────
Write-Host "[4/5] Running fresh npm install (this may take a minute)..." -ForegroundColor Yellow
npm install
if ($LASTEXITCODE -ne 0) {
    Write-Host "      ✗ npm install failed!" -ForegroundColor Red
    exit 1
}
Write-Host "      ✓ npm install complete" -ForegroundColor Green

# ─── 5. Verify everything ────────────────────────────────────────────────
Write-Host "[5/5] Running full verification pipeline..." -ForegroundColor Yellow
Write-Host ""

Write-Host "  → Lint..." -ForegroundColor Cyan
npm run lint
if ($LASTEXITCODE -ne 0) { Write-Host "✗ Lint failed!" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  → Typecheck..." -ForegroundColor Cyan
npm run typecheck
if ($LASTEXITCODE -ne 0) { Write-Host "✗ Typecheck failed!" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  → Tests..." -ForegroundColor Cyan
npm test
if ($LASTEXITCODE -ne 0) { Write-Host "✗ Tests failed!" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  → Build..." -ForegroundColor Cyan
npm run build
if ($LASTEXITCODE -ne 0) { Write-Host "✗ Build failed!" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "✅ ALL GREEN! Ready to commit & push." -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  git add ." -ForegroundColor White
Write-Host "  git commit -m 'fix(ci): ESLint 9 flat config + vitest.config.mts for ESM'" -ForegroundColor White
Write-Host "  git push origin main" -ForegroundColor White
Write-Host ""
