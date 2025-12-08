#!/usr/bin/env python3

# based on https://github.com/Ailyth99/RewindPS4


from mitmproxy import http
from mitmproxy.proxy.layers import tls
import os
import logging
from mitmproxy.addonmanager import Loader
from mitmproxy.log import ALERT

logger = logging.getLogger(__name__)

# Load blocked domains from hosts.txt
BLOCKED_DOMAINS = set()

def load_blocked_domains():
    """Load domains from hosts.txt file"""
    global BLOCKED_DOMAINS
    hosts_path = os.path.join(os.path.dirname(__file__), "../hosts.txt")
    
    try:
        with open(hosts_path, "r") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#"):
                    # Extract domain (handle format: "0.0.0.0 domain.com" or just "domain.com")
                    parts = line.split()
                    domain = parts[-1] if parts else line
                    BLOCKED_DOMAINS.add(domain.lower())
        logger.info(f"[+] Loaded {len(BLOCKED_DOMAINS)} blocked domains from hosts.txt")
    except FileNotFoundError:
        logger.info(f"[!] WARNING: hosts.txt not found at {hosts_path}")
        exit()
    except Exception as e:
        logger.info(f"[!] ERROR loading hosts.txt: {e}")

# Load domains when script initializes
load_blocked_domains()

def is_blocked(hostname: str) -> bool:
    """Check if hostname matches any blocked domain"""
    hostname_lower = hostname.lower()
    for blocked in BLOCKED_DOMAINS:
        if blocked in hostname_lower:
            return True
    return False

def tls_clienthello(data: tls.ClientHelloData) -> None:
    if data.context.server.address:
        hostname = data.context.server.address[0]
        
        # Block domains at TLS layer
        if is_blocked(hostname):
            #flow.kill()
            logger.info(f"[*] Blocked HTTPS connection to: {hostname}")
            raise ConnectionRefusedError(f"[*] Blocked HTTPS connection to: {hostname}")
        else:
            pass
            data.ignore_connection = True
      

def request(flow: http.HTTPFlow) -> None:
    """Handle HTTP/HTTPS requests after TLS handshake"""
    hostname = flow.request.pretty_host
    
    # Check for downgrade redirect (HTTP only)
    # Downgrade target
    EU_REDIRECT = "http://gs2.ww.prod.dl.playstation.net/gs2/ppkgo/prod/CUSA00127_00/108/f_2c294dc5a28917366a122cd32c2d03d000eb2aa27fe651231aaaf143ced665fd/f/EP4350-CUSA00127_00-NETFLIXPOLLUX001-A0153-V0100.json"
    US_REDIRECT = "http://gs2.ww.prod.dl.playstation.net/gs2/ppkgo/prod/CUSA00129_00/185/f_624fc32fe1d54c3062691b7ed42e78ab0c2bbbc73379a53f92fbff4b619d763a/f/UT0007-CUSA00129_00-NETFLIXPOLLUX001-A0153-V0100.json"
    JP_REDIRECT = "http://gs2.ww.prod.dl.playstation.net/gs2/ppkgo/prod/CUSA02988_00/104/f_9e6144c11eab87b3ebf340cce86ae456a135e80f848ead1185eb7a3ec19f0abe/f/JA0010-CUSA02988_00-NETFLIXPOLLUX001-A0153-V0100.json"
    nflix_cusas = ["CUSA00127", "CUSA00129", "CUSA02988"]
    
    if flow.request.scheme == "http" and "gs2.ww.prod.dl.playstation.net" in flow.request.pretty_url:
        if nflix_cusas[0] in flow.request.pretty_url and  ".json" in flow.request.pretty_url:
           
            logger.info(f"[REDIRECT][CUSA00127] {flow.request.pretty_url}")
            logger.info(f"        -> {EU_REDIRECT}")
            flow.request.url = EU_REDIRECT
        
        elif nflix_cusas[1] in flow.request.pretty_url and ".json" in flow.request.pretty_url:
            logger.info(f"[REDIRECT][CUSA00129] {flow.request.pretty_url}")
            logger.info(f"        -> {US_REDIRECT}")
            flow.request.url = US_REDIRECT
            
        elif nflix_cusas[2] in flow.request.pretty_url and ".json" in flow.request.pretty_url:
            logger.info(f"[REDIRECT][CUSA02988] {flow.request.pretty_url}")
            logger.info(f"        -> {JP_REDIRECT}")
            flow.request.url = JP_REDIRECT
            
        elif ".pkg" in flow.request.pretty_url and (nflix_cusas[0] in flow.request.pretty_url or nflix_cusas[1] in flow.request.pretty_url or nflix_cusas[2] in flow.request.pretty_url):
            pass
        else:
            flow.response = http.Response.make( 
                200,
                b"uwu",  # probably don't need this many uwus. just corrupt the response 
                {"Content-Type": "application/x-msl+json"}
            )
            
            logger.info(f"[*] Corrupted Game update response for: {hostname}")
            
        return
    
    # Block other domains from hosts.txt
    if is_blocked(hostname):
        flow.response = http.Response.make( 
            404,
            b"uwu",
        )
        logger.info(f"[*] Blocked HTTP request to: {hostname}")
        return
