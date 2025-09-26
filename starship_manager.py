#!/usr/bin/env python3
import json
import os
import sys
import time
import logging
import subprocess
import random
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from contextlib import contextmanager
import ipaddress

# --- Configuration and Setup ---

SCHEMA_VERSION = 1

def _is_valid_ip(ip_str: str) -> bool:
    """Validate if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def _deep_merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merges dictionaries, returning a new dict."""
    result: Dict[str, Any] = dict(base)
    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result

def load_config() -> Dict[str, Any]:
    """
    Loads configuration from 'ip_config.json' and merges with defaults.
    """
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_config.json")
    
    default_config: Dict[str, Any] = {
        "cache_dir": "~/.cache/starship",
        "cache_expiry": 600,  # NEW: Cache expiry in seconds (10 minutes)
        "timeout": 3,
        "max_retries": 3,
        "abuseipdb_api_key": None,
        "abuseipdb_enabled": True,
        "display_options": { "max_org_length": 20 },
        "logging": { "enabled": False, "level": "INFO", "log_file": "~/.cache/starship/ip_location.log" }
    }

    abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if abuseipdb_api_key:
        default_config["abuseipdb_api_key"] = abuseipdb_api_key

    try:
        with open(config_path, 'r') as f:
            user_config = json.load(f)
        config = _deep_merge_dicts(default_config, user_config)
    except (FileNotFoundError, json.JSONDecodeError):
        config = default_config

    config['cache_dir'] = os.path.expanduser(config['cache_dir'])
    if config.get('logging', {}).get('enabled'):
        log_file = config['logging'].get('log_file')
        if log_file:
            config['logging']['log_file'] = os.path.expanduser(log_file)
            
    return config

def setup_logging(config: Dict[str, Any]) -> Optional[logging.Logger]:
    """
    Configures and sets up the logging system.
    """
    log_config = config.get('logging', {})
    if not log_config.get('enabled'):
        return None

    logger = logging.getLogger(__name__)
    if logger.hasHandlers():
        return logger

    log_level = log_config.get('level', 'INFO').upper()
    log_file = log_config.get('log_file')
    if not log_file:
        return None

    try:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, log_level, logging.INFO))
        return logger
    except OSError:
        return None

# --- Core Data Fetching & Parsing ---

def fetch_ip_info(config: Dict[str, Any], logger: Optional[logging.Logger] = None) -> Optional[Dict[str, Any]]:
    """Fetches public IP information from multiple services concurrently with retry/backoff.

    Returns the first successful result.
    """
    services = [
        {"name": "ipinfo.io", "url": "https://ipinfo.io/json", "parser": parse_ipinfo},
        {"name": "ip-api.com", "url": "https://ip-api.com/json?fields=status,message,countryCode,city,regionName,org,as,query,timezone", "parser": parse_ip_api},
        {"name": "ipify", "url": "https://api.ipify.org?format=json", "parser": parse_ipify},
        {"name": "ifconfig.co", "url": "https://ifconfig.co/json", "parser": parse_ifconfig},
    ]
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; starship-prompt/1.0)'}
    max_retries = max(0, int(config.get('max_retries', 3)))
    timeout = float(config.get('timeout', 3))

    def fetch_service(service: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        service_name = service.get('name', 'unknown')
        for attempt in range(max_retries + 1):
            try:
                req = Request(service["url"], headers=headers)
                with urlopen(req, timeout=timeout) as response:
                    if response.status != 200:
                        continue
                    data = json.loads(response.read().decode('utf-8'))
                result = service["parser"](data)
                if result and result.get("ip"):
                    if logger:
                        logger.info(f"Successfully fetched IP info from {service_name}")
                    return result
            except (URLError, HTTPError, json.JSONDecodeError) as e:
                if logger:
                    logger.warning(f"Service {service_name} attempt {attempt+1} failed: {type(e).__name__}")
                if attempt < max_retries:
                    sleep_s = min(2.0 ** attempt * 0.25 + random.uniform(0, 0.25), 2.5)
                    time.sleep(sleep_s)
            except Exception as e:
                if logger:
                    logger.warning(f"Service {service_name} attempt {attempt+1} failed: unexpected error")
                if attempt < max_retries:
                    time.sleep(0.25)
        return None

    with ThreadPoolExecutor(max_workers=len(services)) as executor:
        future_to_service = {executor.submit(fetch_service, svc): svc for svc in services}
        try:
            for future in as_completed(future_to_service, timeout=timeout + 1):
                try:
                    result = future.result()
                    if result:
                        # Cancel remaining futures
                        for f in future_to_service:
                            if f != future and not f.done():
                                f.cancel()
                        return result
                except Exception as e:
                    if logger:
                        logger.warning(f"Future execution failed: {type(e).__name__}")
                    continue
        except Exception as e:
            if logger:
                logger.warning(f"ThreadPoolExecutor failed: {type(e).__name__}")
    return None

def fetch_abuseipdb_info(ip_address: Optional[str], api_key: Optional[str], logger: Optional[logging.Logger] = None) -> Optional[Dict[str, Any]]:
    """Fetches the abuse score for an IP from AbuseIPDB.com."""
    if not api_key or not ip_address:
        return None

    # Basic IP address validation
    if not _is_valid_ip(ip_address):
        if logger:
            logger.warning("Invalid IP address format")
        return None

    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90'
    headers = {'Accept': 'application/json', 'Key': api_key, 'User-Agent': 'starship-prompt/1.0'}

    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=3) as response:
            if response.status != 200:
                if logger:
                    logger.warning(f"AbuseIPDB returned HTTP {response.status}")
                return None
            data = json.loads(response.read().decode('utf-8'))
        return data.get("data", {})
    except (URLError, HTTPError) as e:
        if logger:
            logger.warning(f"AbuseIPDB network error: {type(e).__name__}")
    except json.JSONDecodeError:
        if logger:
            logger.warning("AbuseIPDB returned invalid JSON")
    except Exception as e:
        if logger:
            logger.warning(f"AbuseIPDB check failed: {type(e).__name__}")
    return None

def parse_ipinfo(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parses the JSON response from ipinfo.io."""
    asn_data = data.get("asn", {})
    return {
        "ip": data.get("ip"),
        "country": data.get("country"),
        "city": data.get("city"),
        "region": data.get("region"),
        "org": data.get("org"),
        "timezone": data.get("timezone"),
        "asn": {
            "id": asn_data.get("asn") if isinstance(asn_data, dict) else None,
            "name": asn_data.get("name") if isinstance(asn_data, dict) else None
        }
    }

def parse_ip_api(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parses the JSON response from ip-api.com."""
    as_string = data.get("as", "")
    as_parts = as_string.split(" ", 1) if isinstance(as_string, str) else []
    return {
        "ip": data.get("query"),
        "country": data.get("countryCode"),
        "city": data.get("city"),
        "region": data.get("regionName"),
        "org": data.get("org"),
        "timezone": data.get("timezone"),
        "asn": {
            "id": as_parts[0] if as_parts else "",
            "name": as_parts[1] if len(as_parts) > 1 else ""
        }
    }

def parse_ipify(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parses the JSON response from api.ipify.org (IP only)."""
    return {"ip": data.get("ip")}

def parse_ifconfig(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parses the JSON response from ifconfig.co/json."""
    # ifconfig.co fields vary; use what is available
    asn_id = data.get("asn") or ""
    org = data.get("asn_org") or data.get("org")
    return {
        "ip": data.get("ip"),
        "country": data.get("country_iso") or data.get("country"),
        "city": data.get("city"),
        "region": data.get("region_name") or data.get("region"),
        "org": org,
        "timezone": data.get("timezone"),
        "asn": {"id": str(asn_id) if asn_id else "", "name": str(org) if org else ""},
    }

# --- Formatting and Display ---

def mask_ip_address(ip_string: Optional[str]) -> Optional[str]:
    """Masks last segment of IPv4/IPv6 address for privacy."""
    if not ip_string or not isinstance(ip_string, str):
        return ip_string

    # IPv4 detection and masking
    if ip_string.count('.') == 3:
        parts = ip_string.split('.')
        try:
            # Validate IPv4 parts are numeric and in valid range
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                parts[-1] = 'x'
                return '.'.join(parts)
        except ValueError:
            pass

    # IPv6 detection and masking (simplified)
    if ':' in ip_string and ip_string.count(':') >= 2:
        parts = ip_string.split(':')
        if parts and len(parts) >= 2:
            parts[-1] = 'x'
            return ':'.join(parts)

    return ip_string

def country_to_flag(country_code: Optional[str]) -> str:
    """Converts a two-letter ISO country code into a flag emoji."""
    if not isinstance(country_code, str) or len(country_code) != 2:
        return "🌐"
    try:
        return "".join(chr(ord(c) + 127397) for c in country_code.upper())
    except (ValueError, OverflowError):
        return "🌐"

def format_location(ip_data: Optional[Dict[str, Any]], config: Dict[str, Any]) -> str:
    """Formats the IP location data into a compact string."""
    if not ip_data or not isinstance(ip_data, dict):
        return "🔌 offline"

    flag = country_to_flag(ip_data.get("country"))
    city = ip_data.get('city')
    country = ip_data.get('country')
    masked_ip = mask_ip_address(ip_data.get('ip'))

    # Prefer city, then country, then masked IP
    location = city or country or masked_ip or 'unknown'
    return f"{flag} {location}"

# --- Status Indicator Functions ---

def get_nordvpn_status() -> str:
    try: result = subprocess.run(['nordvpn', 'status'], capture_output=True, text=True, check=True, timeout=2); return "" if "Status: Connected" in result.stdout else ""
    except Exception: return ""
def get_aws_status() -> str: return "󰸏 " if os.getenv("AWS_PROFILE") or os.getenv("AWS_VAULT") else ""
def get_timezone_status(ip_data: Optional[Dict[str, Any]]) -> str: return f"TZN:{ip_data['timezone']}" if ip_data and ip_data.get("timezone") else ""
def get_asn_status(ip_data: Optional[Dict[str, Any]]) -> str: return f" {ip_data['asn']['id']}" if ip_data and ip_data.get("asn", {}).get("id") else ""
def get_whois_status(ip_data: Optional[Dict[str, Any]]) -> str: return f"ASN:{ip_data['org']}" if ip_data and ip_data.get("org") else ""

# UPDATED: Changed the icons for AbuseIPDB status to be more consistent.
def get_abuse_status(abuse_data: Optional[Dict[str, Any]]) -> str:
    if not abuse_data: return ""
    score = abuse_data.get('abuseConfidenceScore', 0)
    if score > 50:
        icon = "󰯜"  # High risk icon (virus)
    elif score > 0:
        icon = "󰱩"  # Medium risk icon (shield-alert)
    else:
        icon = "󰱧"  # Clean icon (shield-check)
    return f"{icon} {score}"
def get_firewall_status() -> str:
    icon_active, icon_inactive = "🛡️", "󰦝"
    try:
        if sys.platform == "linux": return icon_active if "Status: active" in subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=1).stdout else icon_inactive
        elif sys.platform == "darwin": return icon_active if "Status: Enabled" in subprocess.run(['pfctl', '-s', 'info'], capture_output=True, text=True, timeout=1).stdout else icon_inactive
    except Exception: return ""
    return ""
def get_ssh_agent_status() -> str:
    if not os.getenv("SSH_AUTH_SOCK"): return ""
    try:
        if subprocess.run(['ssh-add', '-l'], capture_output=True, text=True, timeout=1, check=True).stdout.strip(): return "🔑"
    except Exception: return ""
    return ""

# --- Rich Banner Integration ---

def show_warp_banner(config: Dict[str, Any], logger: Optional[logging.Logger] = None) -> None:
    """Display animated 'It's Warp Time!' banner with typewriter effect."""

    # ASCII art for "It's Warp Time!" split into lines
    ascii_lines = [
        "██╗████████╗███████╗    ██╗    ██╗ █████╗ ██████╗ ██████╗     ████████╗██╗███╗   ███╗███████╗██╗",
        "██║╚══██╔══╝██╔════╝    ██║    ██║██╔══██╗██╔══██╗██╔══██╗    ╚══██╔══╝██║████╗ ████║██╔════╝██║",
        "██║   ██║   ███████╗    ██║ █╗ ██║███████║██████╔╝██████╔╝       ██║   ██║██╔████╔██║█████╗  ██║",
        "██║   ██║   ╚════██║    ██║███╗██║██╔══██║██╔══██╗██╔═══╝        ██║   ██║██║╚██╔╝██║██╔══╝  ╚═╝",
        "██║   ██║   ███████║    ╚███╔███╔╝██║  ██║██║  ██║██║            ██║   ██║██║ ╚═╝ ██║███████╗██╗",
        "╚═╝   ╚═╝   ╚══════╝     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝            ╚═╝   ╚═╝╚═╝     ╚═╝╚══════╝╚═╝"
    ]

    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
        from rich.live import Live
        import time

        console = Console()

        # Animation settings from config or defaults
        animation_config = config.get('banner_animation', {})
        char_delay = animation_config.get('char_delay', 0.003)  # Delay between characters
        line_delay = animation_config.get('line_delay', 0.1)   # Delay between lines
        colors = animation_config.get('colors', ['bright_blue', 'cyan', 'bright_cyan', 'blue'])
        enable_animation = animation_config.get('enabled', True)

        if not enable_animation:
            # Show static banner if animation disabled
            ascii_art = "\n".join(ascii_lines)
            banner_text = Text(ascii_art, style="bold bright_blue")
            panel = Panel(banner_text, border_style="bright_cyan", padding=(0, 1))
            console.print(panel)
            return

        # Create empty text object for animation
        animated_text = Text()

        with Live(Panel(animated_text, border_style="bright_cyan", padding=(0, 1)),
                  console=console, refresh_per_second=30) as live:

            for line_idx, line in enumerate(ascii_lines):
                current_line = ""
                color = colors[line_idx % len(colors)]

                # Animate each character in the line
                for char in line:
                    current_line += char

                    # Rebuild the text with all previous complete lines plus current partial line
                    animated_text = Text()
                    for i in range(line_idx):
                        prev_color = colors[i % len(colors)]
                        animated_text.append(ascii_lines[i] + "\n", style=f"bold {prev_color}")

                    # Add current partial line
                    animated_text.append(current_line, style=f"bold {color}")

                    # Update the live display
                    live.update(Panel(animated_text, border_style="bright_cyan", padding=(0, 1)))
                    time.sleep(char_delay)

                # Add newline after completing each line (except the last)
                if line_idx < len(ascii_lines) - 1:
                    animated_text.append("\n")
                    time.sleep(line_delay)

            # Final pulse effect
            for _ in range(3):
                live.update(Panel(animated_text, border_style="bright_magenta", padding=(0, 1)))
                time.sleep(0.2)
                live.update(Panel(animated_text, border_style="bright_cyan", padding=(0, 1)))
                time.sleep(0.2)

        if logger:
            logger.info("Animated warp banner displayed successfully")

    except ImportError:
        # Fallback if rich is not available - display ASCII art directly
        ascii_art = "\n".join(ascii_lines)

        # Simple typewriter fallback using basic terminal
        if config.get('banner_animation', {}).get('enabled', True):
            import sys
            import time
            for line in ascii_lines:
                for char in line:
                    sys.stdout.write(char)
                    sys.stdout.flush()
                    time.sleep(0.01)
                print()  # newline
                time.sleep(0.05)
        else:
            print(ascii_art)

        if logger:
            logger.info("ASCII art banner displayed (rich not available)")

    except Exception as e:
        # Simple fallback for any other errors
        ascii_art = "\n".join(ascii_lines)
        print(ascii_art)

        if logger:
            logger.warning(f"Banner display error: {type(e).__name__}, used ASCII fallback")

# --- Caching Logic ---

def write_cache(config: Dict[str, Any], all_data: Dict[str, Any], logger: Optional[logging.Logger] = None) -> None:
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

def read_cache(config: Dict[str, Any], logger: Optional[logging.Logger] = None) -> Optional[Dict[str, Any]]:
    """Reads and validates the JSON cache file."""
    cache_dir = config.get('cache_dir')
    if not cache_dir or not os.path.exists(cache_dir):
        return None

    cache_file = os.path.join(cache_dir, 'prompt_data.json')
    expiry = config.get('cache_expiry', 600)

    if not os.path.exists(cache_file):
        return None
        
    try:
        with open(cache_file, 'r') as f:
            data = json.load(f)
        
        # Invalidate if schema mismatch
        if data.get('schema_version') != SCHEMA_VERSION:
            if logger: logger.info("Cache schema mismatch; invalidating.")
            return None

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

def handle_update_cache(config: Dict[str, Any], logger: Optional[logging.Logger] = None) -> None:
    """
    Fetches all network data and writes it to the cache.
    This is intended to be run as a background task.
    """
    print("Updating cache...")
    ip_data = fetch_ip_info(config, logger)
    abuse_data = None
    if (
        ip_data
        and ip_data.get("ip")
        and config.get("abuseipdb_api_key")
        and config.get("abuseipdb_enabled", True)
    ):
        abuse_data = fetch_abuseipdb_info(ip_data.get("ip"), config.get("abuseipdb_api_key"), logger)
    
    all_data = {
        "timestamp": time.time(),
        "schema_version": SCHEMA_VERSION,
        "ip_data": ip_data,
        "abuse_data": abuse_data
    }
    write_cache(config, all_data, logger)
    print("Cache updated.")

def handle_banner(config: Dict[str, Any], logger: Optional[logging.Logger] = None) -> None:
    """
    Display the 'It's Warp Time!' banner.
    """
    show_warp_banner(config, logger)

def handle_prompt(config: Dict[str, Any], logger: Optional[logging.Logger]):
    """

    Reads data from cache (or fetches if stale/missing) and prints the prompt.
    """
    cached_data = read_cache(config, logger)
    
    if cached_data is None:
        # If cache is missing or stale, fetch live data
        ip_data = fetch_ip_info(config, logger)
        abuse_data = None
        if (
            ip_data
            and ip_data.get("ip")
            and config.get("abuseipdb_api_key")
            and config.get("abuseipdb_enabled", True)
        ):
            abuse_data = fetch_abuseipdb_info(ip_data.get("ip"), config.get("abuseipdb_api_key"), logger)
        
        # Write the new live data back to the cache for next time
        live_data = {"timestamp": time.time(), "schema_version": SCHEMA_VERSION, "ip_data": ip_data, "abuse_data": abuse_data}
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
        #f"{status_components['asn']}" if status_components['asn'] else None,
        #f"{status_components['whois']}" if status_components['whois'] else None,
        f"{status_components['timezone']}" if status_components['timezone'] else None,
        f"{status_components['abuse']}" if status_components['abuse'] else None,
    ]
    
    print(" ".join(filter(None, parts)))

def main() -> None:
    """Main entry point for the script's command-line interface (CLI)."""
    import argparse

    parser = argparse.ArgumentParser(prog="starship_manager.py", description="Starship prompt manager with dynamic status and system information")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("prompt", help="Print prompt data to stdout")
    subparsers.add_parser("update_cache", help="Update the local cache")
    subparsers.add_parser("banner", help="Display 'It's Warp Time!' banner")

    args = parser.parse_args()

    config = load_config()
    logger = setup_logging(config)

    if args.command == "prompt":
        handle_prompt(config, logger)
    elif args.command == "update_cache":
        handle_update_cache(config, logger)
    elif args.command == "banner":
        handle_banner(config, logger)
    else:
        parser.error("Unknown command")

if __name__ == "__main__":
    main()
