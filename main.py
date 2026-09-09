import urllib.request, urllib.error, rclib

def run(ctx):
    url = ctx.target if "://" in ctx.target else "https://" + ctx.target
    evil = "https://redcell-cors-probe.example"
    ctx.info(f"probing CORS with Origin: {evil}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"redcell","Origin":evil})
        r = urllib.request.urlopen(req, timeout=15)
        h = {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        h = {k.lower(): v for k, v in e.headers.items()}
    except Exception as e:
        ctx.err(f"request failed: {e}"); return 1
    acao = h.get("access-control-allow-origin","")
    acac = h.get("access-control-allow-credentials","").lower()
    if acao == evil and acac == "true":
        ctx.finding("Origin reflected WITH credentials — any site can read authed responses",
                    "high", evidence={"acao": acao, "acac": acac})
    elif acao == evil:
        ctx.finding("Arbitrary Origin reflected in ACAO", "medium", evidence={"acao": acao})
    elif acao == "*" and acac == "true":
        ctx.finding("Wildcard ACAO with credentials (browser-rejected but misconfigured)","low")
    else:
        ctx.info(f"ACAO={acao or '(none)'} — no reflection")
    return 0

rclib.main("cors-tester", "CORS misconfiguration checker", run)
