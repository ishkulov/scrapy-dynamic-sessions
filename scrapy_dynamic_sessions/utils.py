import logging
import re
import base64

from urllib.parse import urlparse, ParseResult

logger = logging.getLogger(__name__)


class Proxy():
    
    def __init__(self, url):
        self.parse_result = urlparse(url)
    
    def __getattr__(self, attr):
        if (hasattr(self.parse_result, attr)):
            return getattr(self.parse_result, attr)
    
    @property
    def proxy_auth(self):
        return f"{self.parse_result.username}:{self.parse_result.password}"

    @property
    def proxy_addr(self):
        return f"{self.parse_result.scheme}://{self.parse_result.hostname}:{self.parse_result.port}"

    @property
    def basic_auth(self):
         return 'Basic ' + base64.b64encode(self.proxy_auth.encode()).decode()
        
    @property
    def __str__(self):
        return self.proxy_addr()
    

def load_proxies(path):
    proxies = {}
    fin = open(path)
    try:
        for line in fin.readlines():
            proxy = Proxy(line.strip())
            proxies[proxy.proxy_addr] = proxy
            
    finally:
        fin.close()
        return proxies


def format_cookie(cookie, request):
    """
    Given a dict consisting of cookie components, return its string representation.
    Decode from bytes if necessary.
    """
    decoded = {}
    for key in ("name", "value", "path", "domain"):
        if cookie.get(key) is None:
            if key in ("name", "value"):
                msg = "Invalid cookie found in request {}: {} ('{}' is missing)"
                logger.warning(msg.format(request, cookie, key))
                return
            continue
        if isinstance(cookie[key], str):
            decoded[key] = cookie[key]
        else:
            try:
                decoded[key] = cookie[key].decode("utf8")
            except UnicodeDecodeError:
                logger.warning("Non UTF-8 encoded cookie found in request %s: %s",
                                request, cookie)
                decoded[key] = cookie[key].decode("latin1", errors="replace")

    cookie_str = f"{decoded.pop('name')}={decoded.pop('value')}"
    for key, value in decoded.items():  # path, domain
        cookie_str += f"; {key.capitalize()}={value}"
    return cookie_str

