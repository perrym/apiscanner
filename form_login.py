########################################################
# APISCAN - API Security Scanner                       #
# Licensed under the AGPL-v3.0                         #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2026  #
# version 5.5 24-06-2026                               #
########################################################



from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import requests

from auth_utils import AuthConfigError

logger = logging.getLogger("form_login")

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None


# ─────────────────────────────────────────────────────────
#  Discovery
# ─────────────────────────────────────────────────────────

def _resolve_spec_url(path: str, spec: dict, base_url: str) -> str:
    servers = spec.get("servers") or []
    if servers:
        server_url = (servers[0].get("url") or "").rstrip("/")
        return urljoin(server_url + "/", path.lstrip("/"))
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def discover_login_url(args, sess: requests.Session, base_url: str) -> Optional[str]:
    # 1. Try swagger spec
    swagger_path = getattr(args, "swagger", None)
    if swagger_path:
        try:
            raw = Path(swagger_path).read_text(encoding="utf-8")
            path_lower = str(swagger_path).lower()
            if path_lower.endswith(('.yml', '.yaml')):
                import yaml as _yaml
                spec = _yaml.safe_load(raw) or {}
            else:
                try:
                    spec = json.loads(raw)
                except json.JSONDecodeError:
                    import yaml as _yaml
                    spec = _yaml.safe_load(raw) or {}

            for path, item in (spec.get("paths") or {}).items():
                if not isinstance(item, dict):
                    continue
                for method, op in item.items():
                    if not isinstance(op, dict):
                        continue
                    op_id = str(op.get("operationId") or "").lower()
                    summary = str(op.get("summary") or "").lower()
                    tags = [t.lower() for t in (op.get("tags") or [])]
                    if any(kw in op_id for kw in ("login", "signin", "authenticate", "auth_token")):
                        return _resolve_spec_url(path, spec, base_url)
                    if any(kw in summary for kw in ("login", "sign in", "authenticate")):
                        return _resolve_spec_url(path, spec, base_url)
                    if any(kw in tags for kw in ("login", "auth", "authentication", "session")):
                        return _resolve_spec_url(path, spec, base_url)
        except Exception:
            pass

    # 2. Try common login paths on the target (most specific first)
    common_paths = [
        "/rest/user/login",
        "/identity/api/auth/login",
        "/api/auth/login",
        "/b2b/v2/authentication/login",
        "/users/v1/login",
        "/api/login",
        "/api/v1/login",
        "/auth/login",
        "/login",
        "/signin",
        "/api/signin",
    ]
    tested_urls: list[str] = []
    for path in common_paths:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        tested_urls.append(url)
        try:
            # Try POST directly (HEAD/GET often returns 404/405 on POST-only endpoints)
            r = sess.post(url, json={}, timeout=3, allow_redirects=False)
            # Skip HTML pages — those are web forms, not API login endpoints
            ct = (r.headers.get("Content-Type") or "").lower()
            if r.status_code in (200, 400, 401, 422) and "text/html" not in ct:
                logger.info("Auto-login: found endpoint → %s (HTTP %s)", url, r.status_code)
                return url
            if r.status_code in (301, 302, 303, 307, 308):
                logger.info("Auto-login: found redirect endpoint → %s (HTTP %s)", url, r.status_code)
                return url
        except Exception:
            continue

    logger.info("Auto-login: probed %d paths, none matched. URLs: %s", len(tested_urls), tested_urls[:5])

    # 3. Try crawling the base URL for HTML login forms
    try:
        r = sess.get(base_url, timeout=5)
        if "text/html" in (r.headers.get("Content-Type") or ""):
            if BeautifulSoup is None:
                logger.warning("Auto-login: HTML page detected but BeautifulSoup not installed")
                return None
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action") or ""
                if action:
                    return urljoin(base_url, action)
            for a in soup.find_all("a", href=True):
                href = str(a.get("href") or "").lower()
                text = (a.get_text() or "").lower()
                if "login" in href or "signin" in href or "login" in text or "sign in" in text:
                    return urljoin(base_url, a["href"])
    except Exception:
        pass

    return None


# ─────────────────────────────────────────────────────────
#  Token extraction
# ─────────────────────────────────────────────────────────

def extract_token_from_response(
    resp: requests.Response,
    token_path: Optional[str] = None,
) -> str:
    # Try explicit token path in JSON (e.g. "authentication.token")
    if token_path:
        try:
            data = resp.json()
            node = data
            for segment in token_path.split("."):
                if isinstance(node, dict):
                    node = node.get(segment)
                elif isinstance(node, list) and segment.isdigit():
                    node = node[int(segment)]
                else:
                    node = None
                    break
            if node and isinstance(node, str) and len(node) > 5:
                logger.info("Auto-login: token extracted via path '%s'", token_path)
                return node
        except Exception:
            pass

    # Auto-detect common token paths in JSON
    try:
        data = resp.json()
        if isinstance(data, dict):
            for path in (
                "authentication.token",
                "authentication.access_token",
                "token",
                "access_token",
                "accessToken",
                "jwt",
                "data.token",
                "data.access_token",
            ):
                node = data
                for seg in path.split("."):
                    node = node.get(seg) if isinstance(node, dict) else None
                    if node is None:
                        break
                if node and isinstance(node, str) and len(node) > 5:
                    logger.info("Auto-login: token auto-detected at '%s'", path)
                    return node
        if isinstance(data, str) and len(data) > 10:
            return data
    except Exception:
        pass

    # Try Authorization header
    auth = resp.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        logger.info("Auto-login: token extracted from Authorization header")
        return token
    if auth and len(auth) > 10:
        return auth

    # Try Set-Cookie
    cookie = resp.headers.get("Set-Cookie") or ""
    if cookie:
        logger.info("Auto-login: using session cookie")
        return ""  # Empty string = session cookies are already in the session

    raise AuthConfigError(
        "Could not extract token from login response. "
        "Use --token-path to specify the JSON path (e.g. 'authentication.token')"
    )


# ─────────────────────────────────────────────────────────
#  Main entry-point
# ─────────────────────────────────────────────────────────

def auto_form_login(args) -> str:
    if BeautifulSoup is None:
        raise AuthConfigError(
            "Form auto-login requires BeautifulSoup4. Install: pip install beautifulsoup4"
        )

    username = getattr(args, "login_username", None)
    password = getattr(args, "login_password", None)

    if not username or not password:
        raise AuthConfigError(
            "--flow form requires --login-username and --login-password"
        )

    login_url = getattr(args, "login_url", None)
    token_path = getattr(args, "token_path", None)
    base_url = getattr(args, "url", None) or ""

    sess = requests.Session()
    if getattr(args, "insecure", False):
        sess.verify = False

    # ── Step 0: Auto-discover login URL if not provided ──
    if not login_url:
        login_url = discover_login_url(args, sess, base_url)
        if login_url:
            logger.info("Auto-login: discovered login URL → %s", login_url)
        else:
            raise AuthConfigError(
                "Could not auto-discover login URL. Provide --login-url manually."
            )

    # If login_url is just the base URL, re-discover the real endpoint
    if login_url and login_url.rstrip("/") == base_url.rstrip("/"):
        logger.info("Auto-login: login URL is base URL — re-discovering API endpoint")
        real_url = discover_login_url(args, sess, base_url)
        if real_url and real_url.rstrip("/") != base_url.rstrip("/"):
            login_url = real_url
            logger.info("Auto-login: redirected to API endpoint → %s", login_url)

    logger.info("Auto-login: fetching %s", login_url)

    # Step 1: Fetch the login page / endpoint
    try:
        resp = sess.get(login_url, timeout=10, allow_redirects=True)
    except requests.RequestException as e:
        raise AuthConfigError(f"Failed to reach login URL {login_url}: {e}")

    ct = (resp.headers.get("Content-Type") or "").lower()

    # ── JSON API login (like Juice Shop /rest/user/login) ──
    if "application/json" in ct or login_url.rstrip("/").endswith("/login"):
        logger.info("Auto-login: detected JSON API login endpoint")
        try:
            for body in (
                {"email": username, "password": password},
                {"username": username, "password": password},
                {"user": username, "password": password},
                {"login": username, "password": password},
            ):
                try:
                    resp2 = sess.post(login_url, json=body, timeout=10, allow_redirects=False)
                    if resp2.status_code < 400:
                        break
                except Exception:
                    continue
            else:
                raise AuthConfigError(
                    f"Login POST to {login_url} failed (status {resp2.status_code})"
                )
        except AuthConfigError:
            raise
        except Exception as e:
            raise AuthConfigError(f"JSON login failed: {e}")

        # Detect HTML response — login URL is likely wrong (homepage, not API endpoint)
        ct2 = (resp2.headers.get("Content-Type") or "").lower()
        resp2_text = resp2.text or ""
        is_html_response = (
            "text/html" in ct2
            or resp2_text[:200].lstrip().startswith(("<!DOCTYPE", "<html", "<!--"))
        )

        if is_html_response:
            logger.warning("Auto-login: JSON login returned HTML, login URL may be wrong")
            fallback_url = urljoin(base_url.rstrip("/") + "/", "/rest/user/login")
            if fallback_url.rstrip("/") != login_url.rstrip("/"):
                logger.info("Auto-login: retrying with %s", fallback_url)
                try:
                    for body in (
                        {"email": username, "password": password},
                        {"username": username, "password": password},
                        {"user": username, "password": password},
                        {"login": username, "password": password},
                    ):
                        try:
                            resp2 = sess.post(fallback_url, json=body, timeout=10, allow_redirects=False)
                            if resp2.status_code < 400:
                                break
                        except Exception:
                            continue
                except Exception:
                    pass

        # Try to extract token from the login response first (before redirect).
        token = None
        try:
            token = extract_token_from_response(resp2, token_path)
        except AuthConfigError as e:
            logger.warning("Token extraction from direct response failed: %s", e)

        if token or token == "":
            if 200 <= resp2.status_code < 300 and not is_html_response:
                # Runtime context only: keep the request that actually authenticated.
                from copy import deepcopy
                args._apiscan_login_request = {"url": login_url, "json": deepcopy(body)}
            return token

        # If no token in direct response, follow the redirect and try again.
        if resp2.status_code in (301, 302, 303, 307, 308):
            redirect_url = resp2.headers.get("Location") or ""
            if redirect_url:
                try:
                    r3 = sess.get(urljoin(login_url, redirect_url), timeout=10)
                    token = extract_token_from_response(r3, token_path)
                    if token or token == "":
                        return token
                except AuthConfigError:
                    pass
                except Exception:
                    pass

        if token or token == "":
            return token

        resp_body_preview = (resp2.text or "")[:300]
        raise AuthConfigError(
            f"Could not extract token from login response (HTTP {resp2.status_code}). "
            f"Response body preview: {resp_body_preview}\n"
            f"Use --token-path to specify the JSON path (e.g. 'authentication.token')"
        )

    # ── HTML form login ──
    if "text/html" not in ct:
        logger.info("Auto-login: no HTML detected, trying JSON POST")
        try:
            resp2 = sess.post(login_url, json={"email": username, "password": password}, timeout=10)
            if resp2.status_code < 400:
                return extract_token_from_response(resp2, token_path)
        except Exception:
            pass
        raise AuthConfigError(
            f"Login page at {login_url} returned {ct[:50]}. "
            "Use --token for manual token or ensure the URL returns a login form."
        )

    soup = BeautifulSoup(resp.text, "html.parser")

    # Step 2: Find the login form
    forms = soup.find_all("form")
    if not forms:
        raise AuthConfigError(f"No <form> found on {login_url}")

    login_form = None
    for form in forms:
        if form.find("input", {"type": "password"}):
            login_form = form
            break
    if not login_form:
        login_form = forms[0]  # fallback

    # Step 3: Auto-detect fields
    action = login_form.get("action") or ""
    method = (login_form.get("method") or "POST").upper()
    form_url = urljoin(login_url, action) if action else login_url

    username_field = None
    password_field = None
    extra_fields: dict[str, str] = {}

    for inp in login_form.find_all("input"):
        name = (inp.get("name") or "").strip()
        inp_type = (inp.get("type") or "text").lower()
        value = inp.get("value") or ""

        if not name:
            continue
        if inp_type in ("submit", "button", "reset", "image"):
            continue

        name_lower = name.lower()
        if inp_type == "password" and not password_field:
            password_field = name
        elif any(kw in name_lower for kw in ("user", "email", "login", "account", "name")):
            if not username_field:
                username_field = name
        elif any(kw in name_lower for kw in ("pass", "pwd", "pin")):
            if not password_field:
                password_field = name
        elif value:
            extra_fields[name] = value
        elif inp_type == "hidden":
            extra_fields[name] = value

    if not password_field:
        raise AuthConfigError(
            "Could not auto-detect password field. Use --flow token with --token instead."
        )

    # Step 4: Build and submit form
    form_data: dict[str, str] = dict(extra_fields)
    if username_field:
        form_data[username_field] = username
        logger.info("Auto-login: detected user field '%s'", username_field)
    form_data[password_field] = password
    logger.info("Auto-login: detected password field '%s'", password_field)
    logger.info("Auto-login: submitting %s %s", method, form_url)

    try:
        if method == "POST":
            resp2 = sess.post(form_url, data=form_data, timeout=10, allow_redirects=True)
        else:
            resp2 = sess.get(form_url, params=form_data, timeout=10, allow_redirects=True)
    except requests.RequestException as e:
        raise AuthConfigError(f"Form submission failed: {e}")

    if resp2.status_code >= 400:
        raise AuthConfigError(
            f"Login form returned HTTP {resp2.status_code}. Check credentials."
        )

    return extract_token_from_response(resp2, token_path)
