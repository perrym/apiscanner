"""Response evidence checks; reflections and redirects are not successful baselines."""
from urllib.parse import urljoin, urlsplit

def redirect_to_host(location, source_url, expected_host):
    try:
        target = urlsplit(urljoin(source_url, str(location).strip()))
        return target.scheme.lower() in ('http', 'https') and (target.hostname or '').lower().rstrip('.') == expected_host.lower().rstrip('.')
    except (ValueError, TypeError):
        return False

def baseline_problem(status):
    if 200 <= status < 300:
        return None
    if 300 <= status < 400:
        return 'Redirect baseline; destination operation not tested'
    if status in (401, 403):
        return 'Authentication or policy blocked baseline'
    if status == 404:
        return 'Route or object unavailable'
    if status in (400, 405, 415, 422):
        return 'Operation input or method rejected'
    return 'Server error or unsuitable baseline'


def baseline_hint(status, authenticated=False):
    """(reason, next_action) for an unsuitable baseline. With authentication configured, a
    401/403 usually means the request input was rejected (IDs, ownership, captcha), not that
    credentials are missing."""
    if authenticated and status in (401, 403):
        return ('Rejected despite configured authentication',
                'Authentication is configured; check operation input (IDs, ownership, captcha) '
                'with --api10-data-file, or the permissions of the account')
    return None, None


def redact_cli_args(arguments):
    sensitive = {'--token','--apikey','--basic-auth','--ntlm','--client-secret',
                 '--client-cert-password','--cert-password','--login-password','--form-login-data','--header'}
    result = []
    redact_next = False
    for argument in arguments:
        value = str(argument)
        if redact_next:
            result.append('[redacted]'); redact_next = False; continue
        flag, sep, supplied = value.partition('=')
        if flag.lower() in sensitive:
            result.append(flag + '=[redacted]' if sep else flag)
            redact_next = not sep
        else:
            result.append(value)
    return result
