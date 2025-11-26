
########################################################
# APISCAN - API Security Scanner                       #
# Licensed under AGPL-V3.0                             #
# Author: Perry Mertens pamsniffer@gmail.com (C) 2025  #
# version 2.2  2-11--2025                             #
########################################################
                                                         
from __future__ import annotations
import logging
import time
import re
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional, Tuple
from urllib.parse import urlparse
import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger("auth_utils")

                       
try:                   
    from requests_ntlm import HttpNtlmAuth                
except Exception:                    
    HttpNtlmAuth = None                

try:                     
    from requests_oauthlib import OAuth2Session                
    from oauthlib.oauth2 import BackendApplicationClient, WebApplicationClient                
except Exception:                    
    OAuth2Session = None                
    BackendApplicationClient = None                
    WebApplicationClient = None                


class AuthConfigError(Exception):
    pass

class _CallbackHandler(BaseHTTPRequestHandler):
    _path_with_query: Optional[str] = None

    def do_GET(self):              
        type(self)._path_with_query = self.requestline.split(" ")[1]
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><body><h3>Authentication complete. You may close this window.</h3></body></html>")

    def log_message(self, format, *args):                           
        return

# ----------------------- Funtion _start_callback_server ----------------------------#
def _start_callback_server(host: str, port: int) -> Tuple[HTTPServer, threading.Thread]:
    server = HTTPServer((host, port), _CallbackHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, t

# ----------------------- Funtion _wait_for_callback ----------------------------#
def _wait_for_callback(server: HTTPServer, timeout: int = 300) -> str:
    for _ in range(timeout * 10):
        if _CallbackHandler._path_with_query:
            host, port = server.server_address
            return f"http://{host}:{port}{_CallbackHandler._path_with_query}"
        threading.Event().wait(0.1)
    raise AuthConfigError("Timed out waiting for OAuth2 redirect callback")


                                                                                    
# ----------------------- Funtion _apply_api_key ----------------------------#
def _apply_api_key(sess: requests.Session, args) -> None:
    api_key = getattr(args, "apikey", None)
    if api_key:
        header = getattr(args, "apikey_header", None) or "X-API-Key"
        sess.headers[header] = api_key.strip()
        logger.debug("API key header applied: %s", header)

# ----------------------- Funtion _apply_mtls ----------------------------#
def _apply_mtls(sess: requests.Session, args) -> None:
    cert = getattr(args, "client_cert", None)
    key = getattr(args, "client_key", None)
    if cert and key:
        if getattr(args, "cert_password", None):
            logger.warning("Provided --cert-password is not used by requests; supply an unencrypted PEM key instead.")
        sess.cert = (cert, key)
        logger.debug("mTLS client cert configured")

# ----------------------- Funtion _format_bearer ----------------------------#
def _format_bearer(token: str) -> str:
    return token if token.startswith("Bearer ") else f"Bearer {token}"

                                                               
# ----------------------- Funtion _oauth_client_credentials ----------------------------#
def _oauth_client_credentials(args) -> str:
    if OAuth2Session is None or BackendApplicationClient is None:
        raise AuthConfigError("OAuth2 dependencies missing. Install: pip install requests-oauthlib oauthlib")
    cid = getattr(args, "client_id", None)
    csec = getattr(args, "client_secret", None)
    token_url = getattr(args, "token_url", None)
    scope = getattr(args, "scope", None)
    missing = [n for n, v in (("client_id", cid), ("client_secret", csec), ("token_url", token_url)) if not v]
    if missing:
        raise AuthConfigError(f"--flow client requires: {', '.join(missing)}")
    client = BackendApplicationClient(client_id=cid)
    oauth = OAuth2Session(client=client, scope=scope.split() if isinstance(scope, str) else scope)
    token = oauth.fetch_token(token_url=token_url, client_id=cid, client_secret=csec, scope=scope)
    return token["access_token"]

# ----------------------- Funtion _oauth_authorization_code ----------------------------#
def _oauth_authorization_code(args) -> str:
    if OAuth2Session is None or WebApplicationClient is None:
        raise AuthConfigError("OAuth2 dependencies missing. Install: pip install requests-oauthlib oauthlib")
    cid = getattr(args, "client_id", None)
    auth_url = getattr(args, "auth_url", None)
    token_url = getattr(args, "token_url", None)
    redirect_uri = getattr(args, "redirect_uri", None)
    scope = getattr(args, "scope", None)

    missing = [n for n, v in (("client_id", cid), ("auth_url", auth_url), ("token_url", token_url), ("redirect_uri", redirect_uri)) if not v]
    if missing:
        raise AuthConfigError(f"--flow auth requires: {', '.join(missing)}")

                                                                               
    parsed = urlparse(redirect_uri)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8765

    server, _t = _start_callback_server(host, port)
    try:
        client = WebApplicationClient(client_id=cid)
        oauth = OAuth2Session(client=client, redirect_uri=redirect_uri, scope=scope.split() if isinstance(scope, str) else scope)
        url, _state = oauth.authorization_url(auth_url)
        logger.info("Opening browser for OAuth2 authorization: %s", url)
        webbrowser.open(url)
        authorization_response = _wait_for_callback(server)
        token = oauth.fetch_token(
            token_url=token_url,
            authorization_response=authorization_response,
            client_secret=getattr(args, "client_secret", None),
            include_client_id=True,
        )
        return token["access_token"]
    finally:
        try:
            server.shutdown()
        except Exception:
            pass


                                                                    
# ----------------------- Funtion configure_authentication ----------------------------#
def configure_authentication(args) -> requests.Session:
    sess = requests.Session()
    insecure = bool(getattr(args, "insecure", False))
    sess.verify = not insecure
    if insecure:
        logger.warning("TLS verification disabled (--insecure). Use only in test labs.")

    
    _apply_api_key(sess, args)
    _apply_mtls(sess, args)

    flow = getattr(args, "flow", None) or "none"

   
    if flow in ("none", None) and getattr(args, "token", None):
        sess.headers["Authorization"] = _format_bearer(args.token.strip())
        logger.info("Bearer token applied (flow=none).")

    if flow == "none" or flow is None:
        return sess

    if flow == "token":
        token = getattr(args, "token", None)
        if not token:
            raise AuthConfigError("--flow token requires --token")
        sess.headers["Authorization"] = _format_bearer(token.strip())
        return sess

    if flow == "client":
        access_token = _oauth_client_credentials(args)
        sess.headers["Authorization"] = f"Bearer {access_token}"
        return sess

    if flow == "basic":
        basic = getattr(args, "basic_auth", None)
        if not basic or ":" not in basic:
            raise AuthConfigError("--flow basic requires --basic-auth user:password")
        user, pwd = basic.split(":", 1)
        sess.auth = HTTPBasicAuth(user, pwd)
        return sess

    if flow == "ntlm":
        ntlm_str = getattr(args, "ntlm", None)
        if not ntlm_str:
            raise AuthConfigError("--flow ntlm requires --ntlm DOMAIN\\user:password (or user:password)")
                                              
        m = re.match(r"(.+)\\(.+):(.+)", ntlm_str)                    
        if m:
            domain, user, pwd = m.groups()
            if HttpNtlmAuth is None:
                raise AuthConfigError("requests-ntlm not installed. Install: pip install requests-ntlm")
            sess.auth = HttpNtlmAuth(f"{domain}\\\\{user}", pwd)
            return sess
        m = re.match(r"([^\\:]+):(.+)", ntlm_str)                         
        if m:
            user, pwd = m.groups()
            if HttpNtlmAuth is None:
                raise AuthConfigError("requests-ntlm not installed. Install: pip install requests-ntlm")
            sess.auth = HttpNtlmAuth(user, pwd)
            return sess
        raise AuthConfigError("Invalid NTLM value. Use DOMAIN\\\\user:password or user:password")

    if flow == "auth":
        access_token = _oauth_authorization_code(args)
        sess.headers["Authorization"] = f"Bearer {access_token}"
        return sess

    raise AuthConfigError(f"Unknown flow: {flow}")
