import ssl
import urllib.error
import urllib.parse
import urllib.request

import rclib


REQUEST_TIMEOUT = 10
DEFAULT_ORIGIN = "https://cors-audit.invalid"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _normalize_target(target):
    url = target if "://" in target else "https://" + target
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be an HTTP or HTTPS URL with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target URLs must not contain credentials")
    if parsed.fragment:
        raise ValueError("target URLs must not contain a fragment")
    parsed.port  # Validate the port before making a request.
    return url


def _normalize_origin(origin):
    parsed = urllib.parse.urlsplit(origin)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("probe origin must be an HTTP or HTTPS origin")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("probe origins must not contain credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("probe origin must contain only a scheme, host, and optional port")

    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    authority = host if port is None or default_port else f"{host}:{port}"
    return f"{scheme}://{authority}"


def _arguments(parser):
    parser.add_argument(
        "--origin",
        default=DEFAULT_ORIGIN,
        help="origin to send (use an origin you control; default is a reserved .invalid origin)",
    )
    parser.add_argument(
        "--authorization",
        help="authorization context required when using --yes; do not include credentials",
    )


def run(ctx):
    authorization = (ctx.args.authorization or "").strip()
    if ctx.args.yes and not authorization:
        ctx.err("--yes requires --authorization with a non-secret authorization context")
        return 2
    if authorization:
        ctx.data["authorization_context_provided"] = True

    try:
        url = _normalize_target(ctx.target)
        origin = _normalize_origin(ctx.args.origin)
    except ValueError as exc:
        ctx.err(str(exc))
        return 2

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "cors-tester", "Origin": origin},
    )
    opener = urllib.request.build_opener(
        _NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            status = response.status
            headers = response.headers
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = exc.headers
        exc.close()
    except Exception as exc:
        ctx.err(f"request failed ({type(exc).__name__})")
        return 1

    normalized_headers = {key.lower(): value.strip() for key, value in headers.items()}
    acao = normalized_headers.get("access-control-allow-origin", "")
    acac = normalized_headers.get("access-control-allow-credentials", "")
    vary = normalized_headers.get("vary", "")
    observation = {
        "http_status": status,
        "origin_sent": origin,
        "access_control_allow_origin": acao or None,
        "access_control_allow_credentials": acac or None,
        "vary": vary or None,
        "assessment": "observed_only",
    }
    ctx.data["cors_observation"] = observation

    ctx.info(f"HTTP status: {status}; probe Origin: {origin}")
    ctx.info(
        f"ACAO={acao or '(none)'}; ACAC={acac or '(none)'}; Vary={vary or '(none)'}"
    )
    if not acao and not acac:
        ctx.info("No Access-Control-Allow-Origin or Access-Control-Allow-Credentials header observed.")
        return 0

    ctx.finding(
        "Observed CORS response headers",
        "info",
        detail="Header observations are not proof that a browser can read authenticated data.",
        **observation,
    )
    if acao == origin and acac.lower() == "true":
        ctx.warn(
            "The probe origin was reflected with credentials enabled; authenticated "
            "response access was not tested."
        )
    elif acao == "*" and acac.lower() == "true":
        ctx.warn(
            "Wildcard ACAO and credentials=true were observed; browsers reject wildcard "
            "origins for credentialed requests."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(
        rclib.main("cors-tester", "Authorized CORS configuration auditor", run, _arguments)
    )
