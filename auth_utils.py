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
    # Configure authentication with permanent SSL bypass for testing
    sess = requests.Session()
    
    # Permanent SSL verification disable met éénmalige waarschuwing
    sess.verify = False
    logger.warning("⚠️  SSL certificate verification is permanently disabled - voor testdoeleinden")
    
    # Schakel specifieke waarschuwingen uit
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # Rest van de authenticatie handlers blijft hetzelfde
    auth_handlers = [
        _handle_client_cert_auth,
        _handle_bearer_token,
        _handle_oauth_client_credentials,
        _handle_oauth_authorization_code,
        _handle_basic_auth,
        _handle_ntlm_auth,
        _handle_api_key
    ]

    for handler in auth_handlers:
        result = handler(args, sess)
        if result:
            return result

    logger.debug("Geen authenticatie geconfigureerd - anonieme toegang")
    return sess

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
    