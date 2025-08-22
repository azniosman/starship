#!/usr/bin/env python3
import json
import os
import sys
import time
import logging
import subprocess
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# --- Configuration and Setup ---

def load_config():
    """
    Loads configuration from 'ip_config.json' and merges with defaults.
    """
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_config.json")
    
    default_config = {
        "cache_dir": "~/.cache/starship",
        "cache_expiry": 600,  # NEW: Cache expiry in seconds (10 minutes)
        "timeout": 3,
        "max_retries": 3,
        "abuseipdb_api_key": None,
        "display_options": { "max_org_length": 20 },
        "logging": { "enabled": False, "level": "INFO", "log_file": "~/.cache/starship/ip_location.log" }
    }

    abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if abuseipdb_api_key:
        default_config["abuseipdb_api_key"] = abuseipdb_api_key

    try:
        with open(config_path, 'r') as f:
            user_config = json.load(f)
        config = {**default_config, **user_config}
    except (FileNotFoundError, json.JSONDecodeError):
        config = default_config

    config['cache_dir'] = os.path.expanduser(config['cache_dir'])
    if config.get('logging', {}).get('enabled'):
        log_file = config['logging'].get('log_file')
        if log_file:
            config['logging']['log_file'] = os.path.expanduser(log_file)
            
    return config

def setup_logging(config):
    """
    Configures and sets up the logging system.
    """
    log_config = config.get('logging', {})
    if not log_config.get('enabled'): return None
    logger = logging.getLogger(__name__)
    if logger.hasHandlers(): return logger
    log_level = log_config.get('level', 'INFO').upper()
    log_file = log_config.get('log_file')
    if not log_file: return None
    try:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handler = logging.FileHandler(log_file)
    except OSError: return None
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(getattr(logging, log_level, logging.INFO))
    return logger

# --- Core Data Fetching & Parsing ---

def fetch_ip_info(config, logger=None):
    """Fetches public IP information from a list of third-party services."""
    services = [
        {"name": "ipinfo.io", "url": "https://ipinfo.io/json", "parser": parse_ipinfo},
        {"name": "ip-api.com", "url": "https://ip-api.com/json?fields=status,message,countryCode,city,regionName,org,as,query,timezone", "parser": parse_ip_api},
    ]
    headers = {'User-Agent': 'Mozilla/5.0'}
    for service in services:
        try:
            req = Request(service["url"], headers=headers)
            with urlopen(req, timeout=config.get('timeout', 3)) as response:
                data = json.loads(response.read().decode('utf-8'))
            result = service["parser"](data)
            if result and result.get("ip"): return result
        except (URLError, HTTPError) as e:
            if logger: logger.warning(f"Service {service['name']} failed: {e}")
            continue
        except json.JSONDecodeError:
            if logger: logger.warning(f"Failed to parse JSON from {service['name']}")
            continue
    return None

def fetch_abuseipdb_info(ip_address, api_key, logger=None):
    """Fetches the abuse score for an IP from AbuseIPDB.com."""
    if not api_key or not ip_address: return None
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90'
    headers = {'Accept': 'application/json', 'Key': api_key}
    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode('utf-8'))
        return data.get("data", {})
    except Exception as e:
        if logger: logger.warning(f"AbuseIPDB check failed: {e}")
    return None

def parse_ipinfo(data):
    """Parses the JSON response from ipinfo.io."""
    asn_data = data.get("asn", {})
    return {"ip": data.get("ip"), "country": data.get("country"), "city": data.get("city"), "region": data.get("region"), "org": data.get("org"), "timezone": data.get("timezone"), "asn": {"id": asn_data.get("asn"), "name": asn_data.get("name")}}

def parse_ip_api(data):
    """Parses the JSON response from ip-api.com."""
    as_string = data.get("as", "")
    as_parts = as_string.split(" ", 1)
    return {"ip": data.get("query"), "country": data.get("countryCode"), "city": data.get("city"), "region": data.get("regionName"), "org": data.get("org"), "timezone": data.get("timezone"), "asn": {"id": as_parts[0] if as_parts else "", "name": as_parts[1] if len(as_parts) > 1 else ""}}

# --- Formatting and Display ---

def mask_ip_address(ip_string):
    """Masks the last octet of an IPv4 address string."""
    if ip_string and ip_string.count('.') == 3:
        parts = ip_string.split('.'); parts[-1] = 'x'; return '.'.join(parts)
    return ip_string

def country_to_flag(country_code):
    """Converts a two-letter ISO country code into a flag emoji."""
    if not isinstance(country_code, str) or len(country_code) != 2: return "🌐"
    return "".join(chr(ord(c) + 127397) for c in country_code.upper())

def format_location(ip_data, config):
    """Formats the IP location data into a compact string."""
    if not ip_data: return "🔌 offline"
    flag = country_to_flag(ip_data.get("country"))
    return f"{flag} {ip_data.get('city', ip_data.get('country', mask_ip_address(ip_data.get('ip'))))}"

# --- Status Indicator Functions ---

def get_nordvpn_status():
    try: result = subprocess.run(['nordvpn', 'status'], capture_output=True, text=True, check=True, timeout=2); return "" if "Status: Connected" in result.stdout else ""
    except Exception: return ""
def get_aws_status(): return "󰸏 " if os.getenv("AWS_PROFILE") or os.getenv("AWS_VAULT") else ""
def get_timezone_status(ip_data): return f"TZN:{ip_data['timezone']}" if ip_data and ip_data.get("timezone") else ""
def get_asn_status(ip_data): return f" {ip_data['asn']['id']}" if ip_data and ip_data.get("asn", {}).get("id") else ""
def get_whois_status(ip_data): return f"ASN:{ip_data['org']}" if ip_data and ip_data.get("org") else ""

# UPDATED: Changed the icons for AbuseIPDB status to be more consistent.
def get_abuse_status(abuse_data):
    if not abuse_data: return ""
    score = abuse_data.get('abuseConfidenceScore', 0)
    if score > 50:
        icon = "󰯜"  # High risk icon (virus)
    elif score > 0:
        icon = "󰱩"  # Medium risk icon (shield-alert)
    else:
        icon = "󰱧"  # Clean icon (shield-check)
    return f"{icon} {score}"
def get_firewall_status():
    icon_active, icon_inactive = "🛡️", "󰦝"
    try:
        if sys.platform == "linux": return icon_active if "Status: active" in subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=1).stdout else icon_inactive
        elif sys.platform == "darwin": return icon_active if "Status: Enabled" in subprocess.run(['pfctl', '-s', 'info'], capture_output=True, text=True, timeout=1).stdout else icon_inactive
    except Exception: return ""
    return ""
def get_ssh_agent_status():
    if not os.getenv("SSH_AUTH_SOCK"): return ""
    try:
        if subprocess.run(['ssh-add', '-l'], capture_output=True, text=True, timeout=1, check=True).stdout.strip(): return "🔑"
    except Exception: return ""
    return ""

# --- Caching Logic ---

def write_cache(config, all_data, logger=None):
    """Writes the given data dictionary to the JSON cache file."""
    cache_dir = config.get('cache_dir')
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, 'prompt_data.json')
    try:
        with open(cache_file, 'w') as f:
            json.dump(all_data, f)
        if logger: logger.info("Cache successfully written.")
    except (IOError, TypeError) as e:
        if logger: logger.error(f"Failed to write cache: {e}")

def read_cache(config, logger=None):
    """Reads and validates the JSON cache file."""
    cache_file = os.path.join(config.get('cache_dir'), 'prompt_data.json')
    expiry = config.get('cache_expiry', 600)
    
    if not os.path.exists(cache_file):
        return None
        
    try:
        with open(cache_file, 'r') as f:
            data = json.load(f)
        
        # Check if cache is stale
        if time.time() - data.get('timestamp', 0) > expiry:
            if logger: logger.info("Cache is stale.")
            return None
        
        if logger: logger.info("Cache is valid.")
        return data
    except (IOError, json.JSONDecodeError) as e:
        if logger: logger.warning(f"Could not read cache: {e}")
        return None

# --- CLI Command Handlers ---

def handle_update_cache(config, logger=None):
    """
    Fetches all network data and writes it to the cache.
    This is intended to be run as a background task.
    """
    print("Updating cache...")
    ip_data = fetch_ip_info(config, logger)
    abuse_data = None
    if ip_data and ip_data.get("ip") and config.get("abuseipdb_api_key"):
        abuse_data = fetch_abuseipdb_info(ip_data["ip"], config["abuseipdb_api_key"], logger)
    
    all_data = {
        "timestamp": time.time(),
        "ip_data": ip_data,
        "abuse_data": abuse_data
    }
    write_cache(config, all_data, logger)
    print("Cache updated.")

def handle_prompt(config, logger):
    """

    Reads data from cache (or fetches if stale/missing) and prints the prompt.
    """
    cached_data = read_cache(config, logger)
    
    if cached_data is None:
        # If cache is missing or stale, fetch live data
        ip_data = fetch_ip_info(config, logger)
        abuse_data = None
        if ip_data and ip_data.get("ip") and config.get("abuseipdb_api_key"):
            abuse_data = fetch_abuseipdb_info(ip_data["ip"], config["abuseipdb_api_key"], logger)
        
        # Write the new live data back to the cache for next time
        live_data = {"timestamp": time.time(), "ip_data": ip_data, "abuse_data": abuse_data}
        write_cache(config, live_data, logger)
    else:
        # Use data from the valid cache
        ip_data = cached_data.get("ip_data")
        abuse_data = cached_data.get("abuse_data")

    # Collect all status components (local statuses are always live)
    status_components = {
        "firewall": get_firewall_status(),
        "vpn": get_nordvpn_status(),
        "ssh": get_ssh_agent_status(),
        "aws": get_aws_status(),
        "location": format_location(ip_data, config),
        "ip": f"({mask_ip_address(ip_data.get('ip'))})" if ip_data else "",
        "timezone": get_timezone_status(ip_data),
        "asn": get_asn_status(ip_data),
        "whois": get_whois_status(ip_data),
        "abuse": get_abuse_status(abuse_data),
    }

    parts = [
        f"{status_components['firewall']}" if status_components['firewall'] else None,
        f"{status_components['vpn']}" if status_components['vpn'] else None,
        f"{status_components['ssh']}" if status_components['ssh'] else None,
        f"{status_components['aws']}" if status_components['aws'] else None,
        f"{status_components['location']}" if status_components['location'] else None,
        f"{status_components['ip']}" if status_components['ip'] else None,
        f"{status_components['asn']}" if status_components['asn'] else None,
        f"{status_components['whois']}" if status_components['whois'] else None,
        #f"{status_components['timezone']}" if status_components['timezone'] else None,
        f"{status_components['abuse']}" if status_components['abuse'] else None,
    ]
    
    print(" ".join(filter(None, parts)))

def main():
    """
    Main entry point for the script's command-line interface (CLI).
    """
    if len(sys.argv) < 2:
        print("Usage: starship_manager.py <command>")
        print("Commands: prompt, update_cache")
        sys.exit(1)

    command = sys.argv[1]
    config = load_config()
    logger = setup_logging(config)

    commands = {
        "prompt": lambda: handle_prompt(config, logger),
        "update_cache": lambda: handle_update_cache(config, logger),
    }

    action = commands.get(command)
    if action:
        action()
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()