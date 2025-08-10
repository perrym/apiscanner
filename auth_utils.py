##################################
# APISCAN - API Security Scanner #
# Licensed under the MIT License #
# Author: Perry Mertens, 2025    #
##################################
import time
import sys
import requests
import webbrowser
import jwt
import time
import logging
from typing import Optional, Tuple
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient, WebApplicationClient
from requests_ntlm import HttpNtlmAuth
import re
from urllib.parse import urlparse
import warnings
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
#from config import SECRET_KEY  # Maak een config module aan
VALIDATE_SIGNATURE = False  # Tijdelijk uitschakelen voor testen

logger = logging.getLogger("apiscan")

# Constants
CALLBACK_PORT = 65432  # Willekeurige vrije poort
SECRET_KEY = "dummy_key" 
def configure_authentication(args) -> requests.Session:
    """
    Configures authentication for the API scanner based on command-line arguments.
    Supported flows:
    - token: Bearer token (--token)
    - client: OAuth2 Client Credentials (--client-id/--client-secret/--token-url)
    - basic: Basic Authentication (--username/--password)
    - ntlm: NTLM Authentication (--username/--password or --ntlm)
    Args:
        args: Parsed command-line arguments (from argparse)

    Returns:
        requests.Session: Configured session with authentication
    """
    sess = requests.Session()
    sess.verify = False  # Disabled SSL verification for testing purposes
    logger.warning("SSL verification is disabled (for testing only)")

    # Backward compatibility: allow --token without --flow
    if hasattr(args, 'token') and args.token and not hasattr(args, 'flow'):
        sess.headers.update({"Authorization": _format_bearer_token(args.token)})
        logger.info("Bearer token used (auto-detected)")
        return sess

    if not hasattr(args, 'flow') or not args.flow:
        logger.error("No authentication flow specified. Use --flow [token|client|basic|ntlm]")
        sys.exit(1)

    if args.flow == "token":
        if not hasattr(args, 'token') or not args.token:
            logger.error("--flow token requires --token")
            sys.exit(1)
        sess.headers.update({"Authorization": _format_bearer_token(args.token)})
        logger.info("Bearer token authentication configured")
        return sess

    elif args.flow == "client":
        required = ['client_id', 'client_secret', 'token_url']
        missing = [r for r in required if not hasattr(args, r) or not getattr(args, r)]
        if missing:
            logger.error(f"--flow client requires: {', '.join(missing)}")
            sys.exit(1)

        try:
            client = BackendApplicationClient(client_id=args.client_id)
            oauth = OAuth2Session(client=client)
            scope = args.scope.split(" ") if hasattr(args, 'scope') and isinstance(args.scope, str) else getattr(args, 'scope', None)

            token = oauth.fetch_token(
                token_url=args.token_url,
                client_id=args.client_id,
                client_secret=args.client_secret,
                scope=scope
            )
            sess.headers.update({"Authorization": f"Bearer {token['access_token']}"})
            logger.info(f"OAuth2 token successfully retrieved from {args.token_url}")
        except Exception as e:
            logger.error(f"OAuth error: {str(e)}")
            sys.exit(1)
        return sess

    elif args.flow == "basic":
        if not hasattr(args, 'username') or not hasattr(args, 'password') or not args.username or not args.password:
            logger.error("--flow basic requires --username and --password")
            sys.exit(1)
        sess.auth = HTTPBasicAuth(args.username, args.password)
        logger.info("Basic authentication configured")
        return sess

    elif args.flow == "ntlm":
        if hasattr(args, 'ntlm') and args.ntlm:
            try:
                domain, user, pwd = re.match(r"(.+)\\(.+):(.+)", args.ntlm).groups()
                sess.auth = HttpNtlmAuth(f"{domain}\\{user}", pwd)
            except Exception:
                logger.error("Invalid NTLM format. Use: DOMAIN\\username:password")
                sys.exit(1)
        elif hasattr(args, 'username') and hasattr(args, 'password') and args.username and args.password:
            sess.auth = HttpNtlmAuth(args.username, args.password)
        else:
            logger.error("--flow ntlm requires --ntlm DOMAIN\\user:pwd OR --username and --password")
            sys.exit(1)
        logger.info("NTLM authentication configured")
        return sess

    logger.error(f"Unknown flow type: {args.flow}. Use one of: token, client, basic, ntlm")
    sys.exit(1)


def _format_bearer_token(token: str) -> str:
    """Formatteert een token als 'Bearer token' indien nodig"""
    return f"Bearer {token}" if not token.startswith("Bearer ") else token

def _get_ssl_verification_setting(args) -> bool:
    #Determine SSL verification setting from arguments
    return not getattr(args, 'insecure', False)

def _handle_client_cert_auth(args, session: requests.Session) -> Optional[requests.Session]:
    # Improved client certificate authentication
    if args.client_cert and args.client_key:
        try:
            session.cert = (args.client_cert, args.client_key)
            if args.cert_password:
                session.cert += (args.cert_password,)
            logger.debug("Clientcertificaat authenticatie geconfigureerd")
            return session
        except (FileNotFoundError, PermissionError) as e:
            logger.error(f"Certificaatfout: {str(e)}")
            sys.exit(1)
    return None

def _handle_oauth_client_credentials(args, session: requests.Session) -> Optional[requests.Session]:
    # Implements OAuth2 Client Credentials Flow
    if not all([args.client_id, args.client_secret, args.token_url, getattr(args, 'flow', None) == "client"]):
        return None

    try:
        client = BackendApplicationClient(client_id=args.client_id)
        oauth = OAuth2Session(client=client)

        token = oauth.fetch_token(
            token_url=args.token_url,
            client_id=args.client_id,
            client_secret=args.client_secret
        )

        _transfer_session_settings(session, oauth)
        logger.debug("OAuth2 Client Credentials Flow voltooid")
        return oauth
    except Exception as e:
        logger.error(f"OAuth2 Client Credentials fout: {str(e)}")
        sys.exit(1)



def _handle_bearer_token(args, session: requests.Session) -> Optional[requests.Session]:
    # Secure Bearer token configuration
    if args.token:
        token = args.token.strip()
        if _validate_bearer_token(token):
            session.headers["Authorization"] = f"Bearer {token}" if not token.startswith("Bearer ") else token
            logger.debug("Bearer token geconfigureerd (JWT gedetecteerd)")
        else:
            logger.error("Ongeldig token formaat")
            sys.exit(1)
    return None

def _validate_bearer_token(token: str) -> bool:
    # Relaxed validation for test tokens
    if not token:
        return False

    # Als signaturevalidatie aanstaat, controleer of het echt een JWT is
    if VALIDATE_SIGNATURE:
        if len(token.split(".")) != 3:
            return False
        try:
            jwt.decode(token, key=SECRET_KEY, algorithms=["RS256"])
        except jwt.PyJWTError:
            return False

    return True


    
def _handle_basic_auth(args, session: requests.Session) -> Optional[requests.Session]:
    # Improved Basic auth validation
    if args.basic_auth:
        try:
            user, pwd = _validate_basic_auth_format(args.basic_auth)
            session.auth = HTTPBasicAuth(user, pwd)
            logger.debug("Basic authenticatie geconfigureerd")
            return session
        except ValueError as e:
            logger.error(str(e))
            sys.exit(1)
    return None

def _validate_basic_auth_format(basic_auth: str) -> Tuple[str, str]:
    # Stricter validation
    if ":" not in basic_auth:
        raise ValueError("Basic auth formaat moet 'gebruiker:wachtwoord' zijn")
    
    user, pwd = basic_auth.split(":", 1)
    if not user or not pwd:
        raise ValueError("Gebruikersnaam/wachtwoord mag niet leeg zijn")
    
    return user, pwd

def _handle_oauth_authorization_code(args, session: requests.Session) -> Optional[requests.Session]:
    # Automated OAuth2 Authorization Code flow
    if not all([args.client_id, args.token_url, args.auth_url, args.redirect_uri, getattr(args, 'flow', None) == "auth"]):
        return None

    try:
        # Start callback server
        callback_server = _start_callback_server()
        
        client = WebApplicationClient(client_id=args.client_id)
        oauth = OAuth2Session(
            client=client,
            redirect_uri=args.redirect_uri,
            scope=args.scope or []
        )
        
        auth_url, state = oauth.authorization_url(args.auth_url)
        logger.info(f"Open browser voor authenticatie: {auth_url}")
        webbrowser.open(auth_url)
        
        # Wacht op callback
        callback_params = _wait_for_callback(callback_server)
        
        # Token exchange
        _transfer_session_settings(session, oauth)
        token = oauth.fetch_token(
            token_url=args.token_url,
            authorization_response=callback_params,
            client_secret=args.client_secret,
            include_client_id=True
        )
        
        logger.debug("OAuth2 Authorization Code flow voltooid")
        return oauth
    except Exception as e:
        logger.error(f"OAuth-fout: {str(e)}")
        sys.exit(1)
    finally:
        if callback_server:
            callback_server.shutdown()

def _handle_ntlm_auth(args, session: requests.Session) -> Optional[requests.Session]:
    # NTLM authentication (e.g., for internal APIs with Windows auth)
    if args.ntlm:
        try:
            match = re.match(r"(.+)\\\\(.+):(.+)", args.ntlm)
            if not match:
                raise ValueError("NTLM formaat moet zijn: domein\\gebruikersnaam:wachtwoord")

            domain, user, pwd = match.group(1), match.group(2), match.group(3)
            session.auth = HttpNtlmAuth(f"{domain}\\{user}", pwd)
            logger.debug("NTLM authenticatie geconfigureerd")
            return session
        except Exception as e:
            logger.error(f"NTLM authenticatie fout: {str(e)}")
            sys.exit(1)
    return None

def _handle_api_key(args, session: requests.Session) -> Optional[requests.Session]:
    # Header-based API key authentication
    if args.apikey:
        key = args.apikey.strip()
        header = args.apikey_header or "X-API-Key"
        session.headers[header] = key
        logger.debug(f"API key geconfigureerd in header '{header}'")
        return session
    return None



class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.server.callback_params = self.path
        self.wfile.write(b"Authentication complete! You may close this window.")

def _start_callback_server():
    server = HTTPServer(('localhost', CALLBACK_PORT), CallbackHandler)
    thread = Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    return server

def _wait_for_callback(server):
    while not hasattr(server, 'callback_params'):
        time.sleep(0.1)
    return server.callback_params

def _transfer_session_settings(source: requests.Session, destination: requests.Session) -> None:
    # Secure transfer of session settings
    destination.headers.update({k: v for k, v in source.headers.items() if k.lower() != 'authorization'})
    destination.cert = source.cert
    destination.verify = source.verify
    destination.proxies.update(source.proxies)
    