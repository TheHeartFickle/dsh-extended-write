# Install the plugin into an ISOLATED profile (ext-test) and boot a real
# headless instance against it. Never touches the web profile.
# Full access needed: spawns node/pnpm and writes a new profile under ~/.dsh.

$ErrorActionPreference = 'Continue'
$profiles = Join-Path $env:USERPROFILE '.dsh\profiles'
$test = Join-Path $profiles 'ext-test'
$plugin = 'D:\Project\DeepSeek-Harness\dsh-extended-write'
$pnpm = Join-Path $env:APPDATA 'npm\node_modules\pnpm\bin\pnpm.mjs'
$dshBin = Join-Path $env:APPDATA 'npm\node_modules\@deepseek-ai\dsh\lib\bin.js'
function Note($l) { Write-Host $l }

Note '=== [1] create isolated profile ext-test ==='
if (-not (Test-Path (Join-Path $test 'package.json'))) {
  if (Test-Path (Join-Path $profiles 'headless\package.json')) {
    New-Item -ItemType Directory -Force -Path $test | Out-Null
    Copy-Item (Join-Path $profiles 'headless\package.json') $test
    Copy-Item (Join-Path $profiles 'headless\cordis.patch.yml') $test -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $profiles 'headless\cordis.yml') $test -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $profiles 'headless\pnpm-workspace.yaml') $test -ErrorAction SilentlyContinue
    Note 'copied from existing headless profile'
  } else {
    & node $dshBin --profile ext-test --from-default-profile headless --dump-config *> $null
    Note ("from-default-profile init exit={0}" -f $LASTEXITCODE)
  }
} else { Note 'ext-test already exists, reuse' }

Note '=== [2] add plugin as link dep + bundle ==='
$pkgPath = Join-Path $test 'package.json'
$pkg = Get-Content $pkgPath -Raw | ConvertFrom-Json
if (-not ($pkg.dependencies.PSObject.Properties.Name -contains '@the-heart-fickle/dsh-extended-write')) {
  $pkg.dependencies | Add-Member -NotePropertyName '@the-heart-fickle/dsh-extended-write' -NotePropertyValue 'link:D:/Project/DeepSeek-Harness/dsh-extended-write'
  $pkg.dsh.profile.bundles += '@the-heart-fickle/dsh-extended-write'
  ($pkg | ConvertTo-Json -Depth 16) | Set-Content $pkgPath -Encoding utf8
  Note 'dependency + bundle added'
} else { Note 'already present' }

Note '=== [3] pnpm install (isolated profile) ==='
& node $pnpm install --dir $test 2>&1 | Select-Object -Last 6 | Write-Host
Note ("install exit={0}" -f $LASTEXITCODE)

Note '=== [4] composed tree contains our rows ==='
$overlay = Join-Path $plugin 'testdata\headless.overlay.yml'
$dump = & node $dshBin --profile ext-test --dump-config --patch $overlay 2>&1
$dumpText = $dump | Out-String
Note ("dump exit={0} extended-sandbox-policy: {1}" -f $LASTEXITCODE, ($dumpText -match 'extended-sandbox-policy'))
if ($LASTEXITCODE -ne 0) { $dump | Select-Object -Last 25 | Write-Host }

Note '=== [5] boot real instance, agent runs the two probes ==='
$ws = Join-Path $plugin 'testdata\ws'
New-Item -ItemType Directory -Force -Path $ws | Out-Null
Set-Location $ws
$cache2 = Join-Path $env:LOCALAPPDATA 'npm-cache\dsh-e2e-probe.txt'
$outside2 = Join-Path $env:USERPROFILE 'dsh-e2e-outside.txt'
Remove-Item $cache2, $outside2 -Force -ErrorAction SilentlyContinue
$task = 'Run these two pwsh commands in order, then report the exact output of each. 1) Set-Content -LiteralPath (Join-Path $env:LOCALAPPDATA ''npm-cache\dsh-e2e-probe.txt'') -Value ''probe''; Write-Output CACHE-WRITE-OK  2) Set-Content -LiteralPath (Join-Path $env:USERPROFILE ''dsh-e2e-outside.txt'') -Value ''probe''; Write-Output OUTSIDE-WRITE-OK'
& node $dshBin --profile ext-test --patch $overlay $task 2>&1 | Tee-Object -Variable boot | Select-Object -Last 30 | Write-Host
Note ("boot exit={0}" -f $LASTEXITCODE)
Note ("cache probe exists: {0} <-- must be True" -f (Test-Path $cache2))
Note ("outside probe exists: {0} <-- must be False" -f (Test-Path $outside2))
if ($LASTEXITCODE -ne 0) {
  Note '--- startup diagnostics if any ---'
  $log = Get-ChildItem (Join-Path $env:USERPROFILE '.dsh\logs') -Filter 'startup-*.log' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($log) { Note $log.FullName }
}
Note 'done'
