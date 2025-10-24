#!/usr/bin/env python3
"""
Starship Prompt Manager

A comprehensive security and system status monitoring tool for the Starship prompt.
Provides real-time information about firewall, VPN, antivirus, and other security tools.
"""

import json
import os
import sys
import time
import logging
import subprocess
import random
from typing import Any, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import ipaddress

# Import our custom modules
from starship_constants import (
    ConfigDefaults, StatusIcons, IPServices, 
    PlatformDetector, RetryConfig, ValidationRules
)
from starship_platform import PlatformSecurityChecker
from starship_network import IPFetcher, AbuseIPDBClient, NetworkStatusChecker

# --- Configuration and Setup ---

SCHEMA_VERSION = ConfigDefaults.SCHEMA_VERSION

def _is_valid_ip(ip_str: str) -> bool:
    """
    Validate if a string represents a valid IP address.
    
    Supports both IPv4 and IPv6 address formats. Uses the ipaddress module
    for robust validation.
    
    Args:
        ip_str: String to validate as an IP address
        
    Returns:
        True if the string is a valid IP address, False otherwise
        
    Examples:
        >>> _is_valid_ip("192.168.1.1")
        True
        >>> _is_valid_ip("2001:db8::1")
        True
        >>> _is_valid_ip("invalid")
        False
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def _deep_merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge two dictionaries, with override values taking precedence.
    
    Creates a new dictionary by merging the base dictionary with the override
    dictionary. For nested dictionaries, the merge is performed recursively.
    Override values completely replace base values for non-dict types.
    
    Args:
        base: Base dictionary to merge from
        override: Override dictionary with values that take precedence
        
    Returns:
        New dictionary containing the merged result
        
    Examples:
        >>> base = {"a": 1, "b": {"c": 2, "d": 3}}
        >>> override = {"b": {"c": 4}, "e": 5}
        >>> _deep_merge_dicts(base, override)
        {"a": 1, "b": {"c": 4, "d": 3}, "e": 5}
    """
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
    Load configuration from 'ip_config.json' and merge with defaults.
    
    Loads user configuration from ip_config.json file and merges it with
    sensible defaults. Validates all configuration values and expands user paths.
    
    Returns:
        Dictionary containing validated configuration
        
    Raises:
        No exceptions are raised; all errors are handled gracefully.
    """
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip_config.json")
    
    # Build default configuration from constants
    default_config: Dict[str, Any] = {
        "cache_dir": ConfigDefaults.CACHE_DIR,
        "cache_expiry": ConfigDefaults.CACHE_EXPIRY,
        "timeout": ConfigDefaults.TIMEOUT,
        "max_retries": ConfigDefaults.MAX_RETRIES,
        "abuseipdb_api_key": None,
        "abuseipdb_enabled": ConfigDefaults.ABUSEIPDB_ENABLED,
        "display_mode": ConfigDefaults.DISPLAY_MODE,
        "display_options": {"max_org_length": ConfigDefaults.MAX_ORG_LENGTH},
        "text_colors": ConfigDefaults.DEFAULT_TEXT_COLORS.copy(),
        "logging": ConfigDefaults.DEFAULT_LOGGING.copy()
    }

    # Load API key from environment
    abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if abuseipdb_api_key:
        default_config["abuseipdb_api_key"] = abuseipdb_api_key

    try:
        with open(config_path, 'r') as f:
            user_config = json.load(f)
        config = _deep_merge_dicts(default_config, user_config)
    except (FileNotFoundError, json.JSONDecodeError):
        config = default_config

    # Validate and normalize configuration
    config = _validate_config(config)
    
    # Expand user paths
    config['cache_dir'] = os.path.expanduser(config['cache_dir'])
    if config.get('logging', {}).get('enabled'):
        log_file = config['logging'].get('log_file')
        if log_file:
            config['logging']['log_file'] = os.path.expanduser(log_file)
            
    return config

def _validate_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate configuration values and provide sensible defaults.
    
    Validates all configuration parameters against their expected types and ranges,
    replacing invalid values with sensible defaults.
    
    Args:
        config: Configuration dictionary to validate
        
    Returns:
        Validated configuration dictionary
    """
    # Validate cache_expiry (must be positive integer)
    if not ValidationRules.is_positive_number(config.get('cache_expiry')):
        config['cache_expiry'] = ConfigDefaults.CACHE_EXPIRY
    
    # Validate timeout (must be positive number)
    if not ValidationRules.is_positive_number(config.get('timeout')):
        config['timeout'] = ConfigDefaults.TIMEOUT
    
    # Validate max_retries (must be non-negative integer)
    if not ValidationRules.is_non_negative_integer(config.get('max_retries')):
        config['max_retries'] = ConfigDefaults.MAX_RETRIES
    
    # Validate abuseipdb_enabled (must be boolean)
    if not isinstance(config.get('abuseipdb_enabled'), bool):
        config['abuseipdb_enabled'] = ConfigDefaults.ABUSEIPDB_ENABLED
    
    # Validate logging level
    log_level = config.get('logging', {}).get('level', '')
    if not ValidationRules.is_valid_log_level(log_level):
        config.setdefault('logging', {})['level'] = ConfigDefaults.DEFAULT_LOGGING['level']
    
    # Validate display mode
    display_mode = config.get('display_mode', ConfigDefaults.DISPLAY_MODE)
    if not ValidationRules.is_valid_display_mode(display_mode):
        config['display_mode'] = ConfigDefaults.DISPLAY_MODE
    
    return config

def get_status_display(icon: str, text: str, config: Dict[str, Any], status_type: str = "") -> str:
    """Return either icon or text based on display mode configuration."""
    display_mode = config.get('display_mode', 'icons')
    if display_mode == 'icons':
        return icon
    else:
        # Apply color to text if available
        if status_type and config.get('text_colors', {}).get(status_type):
            color = config['text_colors'][status_type]
            return f"\033[{_get_color_code(color)}m{text}\033[0m"
        return text

def _get_color_code(color: str) -> str:
    """Convert color name to ANSI color code."""
    color_map = {
        'black': '30',
        'red': '31',
        'green': '32',
        'yellow': '33',
        'blue': '34',
        'magenta': '35',
        'cyan': '36',
        'white': '37',
        'bright_black': '90',
        'bright_red': '91',
        'bright_green': '92',
        'bright_yellow': '93',
        'bright_blue': '94',
        'bright_magenta': '95',
        'bright_cyan': '96',
        'bright_white': '97',
        'orange': '38;5;208',  # Orange using 256-color palette
        'purple': '38;5;141'   # Purple using 256-color palette
    }
    return color_map.get(color.lower(), '37')  # Default to white

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
    """
    Fetch public IP information from multiple services concurrently.
    
    This function attempts to fetch IP information from multiple services
    in parallel and returns the first successful result. It implements
    retry logic with exponential backoff and jitter for network resilience.
    
    Args:
        config: Configuration dictionary containing:
            - timeout: Request timeout in seconds (default: 3)
            - max_retries: Maximum retry attempts (default: 3)
        logger: Optional logger instance for debugging
        
    Returns:
        Dictionary containing IP information with keys:
            - ip: Public IP address
            - country: Two-letter country code
            - city: City name
            - region: Region/state name
            - org: Organization/ISP name
            - timezone: Timezone identifier
            - asn: Dictionary with ASN ID and name
            
        Returns None if all services fail or timeout.
        
    Raises:
        No exceptions are raised; all errors are logged and handled gracefully.
    """
    fetcher = IPFetcher(config, logger)
    return fetcher.fetch_ip_info()

def fetch_abuseipdb_info(ip_address: Optional[str], api_key: Optional[str], logger: Optional[logging.Logger] = None) -> Optional[Dict[str, Any]]:
    """
    Fetch abuse score for an IP address from AbuseIPDB.
    
    Args:
        ip_address: IP address to check
        api_key: AbuseIPDB API key
        logger: Optional logger instance
        
    Returns:
        Dictionary with abuse information or None
    """
    client = AbuseIPDBClient(api_key, logger)
    return client.fetch_abuse_info(ip_address)

def parse_ipinfo(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse JSON response from ipinfo.io API.
    
    Extracts IP information from the ipinfo.io API response and normalizes
    it into a standard format. Handles ASN data extraction from nested objects.
    
    Args:
        data: Raw JSON response from ipinfo.io API
        
    Returns:
        Dictionary containing normalized IP information:
            - ip: Public IP address
            - country: Two-letter country code
            - city: City name
            - region: Region/state name
            - org: Organization/ISP name
            - timezone: Timezone identifier
            - asn: Dictionary with ASN ID and name
            
    Example:
        >>> data = {"ip": "192.168.1.1", "country": "US", "city": "New York"}
        >>> parse_ipinfo(data)
        {"ip": "192.168.1.1", "country": "US", "city": "New York", ...}
    """
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
    """
    Parse JSON response from ip-api.com API.
    
    Extracts IP information from the ip-api.com API response and normalizes
    it into a standard format. Handles ASN data parsing from string format.
    
    Args:
        data: Raw JSON response from ip-api.com API
        
    Returns:
        Dictionary containing normalized IP information:
            - ip: Public IP address (from 'query' field)
            - country: Two-letter country code (from 'countryCode' field)
            - city: City name
            - region: Region/state name (from 'regionName' field)
            - org: Organization/ISP name
            - timezone: Timezone identifier
            - asn: Dictionary with parsed ASN ID and name
            
    Example:
        >>> data = {"query": "192.168.1.1", "countryCode": "US", "city": "New York"}
        >>> parse_ip_api(data)
        {"ip": "192.168.1.1", "country": "US", "city": "New York", ...}
    """
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
    """
    Parse JSON response from api.ipify.org API.
    
    This service only provides IP address information, so the result is minimal.
    Used as a fallback when other services fail.
    
    Args:
        data: Raw JSON response from api.ipify.org API
        
    Returns:
        Dictionary containing only IP information:
            - ip: Public IP address
            
    Example:
        >>> data = {"ip": "192.168.1.1"}
        >>> parse_ipify(data)
        {"ip": "192.168.1.1"}
    """
    return {"ip": data.get("ip")}

def parse_ifconfig(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse JSON response from ifconfig.co API.
    
    Extracts IP information from the ifconfig.co API response and normalizes
    it into a standard format. Handles variable field names and missing data.
    
    Args:
        data: Raw JSON response from ifconfig.co API
        
    Returns:
        Dictionary containing normalized IP information:
            - ip: Public IP address
            - country: Two-letter country code (from 'country_iso' or 'country')
            - city: City name
            - region: Region/state name (from 'region_name' or 'region')
            - org: Organization/ISP name (from 'asn_org' or 'org')
            - timezone: Timezone identifier
            - asn: Dictionary with ASN ID and name
            
    Example:
        >>> data = {"ip": "192.168.1.1", "country_iso": "US", "city": "New York"}
        >>> parse_ifconfig(data)
        {"ip": "192.168.1.1", "country": "US", "city": "New York", ...}
    """
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
    """
    Mask the last segment of an IP address for privacy protection.
    
    Replaces the last octet of IPv4 addresses or the last segment of IPv6
    addresses with 'x' to provide privacy while maintaining network identification.
    
    Args:
        ip_string: IP address string to mask
        
    Returns:
        Masked IP address string or original string if masking fails
        
    Examples:
        >>> mask_ip_address("192.168.1.100")
        "192.168.1.x"
        >>> mask_ip_address("2001:db8::1")
        "2001:db8::x"
        >>> mask_ip_address("invalid")
        "invalid"
    """
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
    """
    Convert a two-letter ISO country code into a flag emoji.
    
    Uses Unicode regional indicator symbols to create flag emojis from
    ISO 3166-1 alpha-2 country codes. Returns a world emoji for invalid codes.
    
    Args:
        country_code: Two-letter ISO country code (e.g., "US", "GB", "JP")
        
    Returns:
        Flag emoji string or world emoji (🌐) for invalid codes
        
    Examples:
        >>> country_to_flag("US")
        "🇺🇸"
        >>> country_to_flag("GB")
        "🇬🇧"
        >>> country_to_flag("invalid")
        "🌐"
    """
    if not isinstance(country_code, str) or len(country_code) != 2:
        return "🌐"
    try:
        return "".join(chr(ord(c) + 127397) for c in country_code.upper())
    except (ValueError, OverflowError):
        return "🌐"

def format_location(ip_data: Optional[Dict[str, Any]], config: Dict[str, Any], vpn_status: str = "") -> str:
    """
    Format IP location data into a compact display string.
    
    Creates a user-friendly location display with country flag and location name.
    Handles VPN status to show appropriate location information.
    
    Args:
        ip_data: Dictionary containing IP location information
        config: Configuration dictionary for display settings
        vpn_status: VPN status string to determine location display
        
    Returns:
        Formatted location string with flag and location name
        
    Examples:
        >>> ip_data = {"country": "US", "city": "New York"}
        >>> format_location(ip_data, config, "")
        "🇺🇸 New York"
        >>> format_location(None, config, "")
        "🔌 offline"
    """
    if not ip_data or not isinstance(ip_data, dict):
        return "🔌 offline"

    flag = country_to_flag(ip_data.get("country"))
    city = ip_data.get('city')
    country = ip_data.get('country')
    masked_ip = mask_ip_address(ip_data.get('ip'))

    # Determine if VPN is active based on vpn_status
    vpn_active = "VPN+" in vpn_status or "🔒" in vpn_status
    
    # Prefer city, then country, then masked IP
    location = city or country or masked_ip or 'unknown'
    
    if vpn_active:
        # When VPN is active, show VPN exit location
        return f"{flag} {location}"
    else:
        # When not on VPN, show local location
        return f"{flag} {location}"

# --- Status Indicator Functions ---

def get_nordvpn_status(config: Dict[str, Any]) -> str:
    """Check NordVPN connection status."""
    try:
        # First try CLI if available
        result = subprocess.run(['nordvpn', 'status'], capture_output=True, text=True, check=True, timeout=2)
        if "Status: Connected" in result.stdout:
            return get_status_display("🔒", "VPN+", config, "vpn")
        else:
            return get_status_display("🔓", "VPN-", config, "vpn")
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback: Check for NordVPN GUI process
        try:
            result = subprocess.run(['pgrep', '-f', 'NordVPN'], capture_output=True, text=True, timeout=1)
            if result.returncode == 0 and result.stdout.strip():
                # Additional check: look for VPN tunnel interfaces
                tunnel_result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=1)
                if tunnel_result.returncode == 0:
                    # Check for common VPN tunnel interfaces
                    tunnel_interfaces = ['utun', 'tun', 'tap']
                    for interface in tunnel_interfaces:
                        if interface in tunnel_result.stdout:
                            return get_status_display("🔒", "VPN+", config, "vpn")
                # If NordVPN process is running but no tunnel, assume connected
                return get_status_display("🔒", "VPN+", config, "vpn")
        except Exception:
            pass
    except Exception:
        pass
    return get_status_display("🔓", "VPN-", config, "vpn")

def get_aws_status(config: Dict[str, Any]) -> str:
    """Check if AWS profile/vault is active."""
    if os.getenv("AWS_PROFILE") or os.getenv("AWS_VAULT"):
        return get_status_display("☁️", "AWS+", config, "aws")
    return ""

def get_timezone_status(ip_data: Optional[Dict[str, Any]]) -> str:
    """Get timezone from IP data."""
    return f"TZN:{ip_data['timezone']}" if ip_data and ip_data.get("timezone") else ""

def get_asn_status(ip_data: Optional[Dict[str, Any]]) -> str:
    """Get ASN ID from IP data."""
    return f"🌐 {ip_data['asn']['id']}" if ip_data and ip_data.get("asn", {}).get("id") else ""

def get_whois_status(ip_data: Optional[Dict[str, Any]]) -> str:
    """Get organization info from IP data."""
    return f"ASN:{ip_data['org']}" if ip_data and ip_data.get("org") else ""

def get_abuse_status(abuse_data: Optional[Dict[str, Any]], config: Dict[str, Any]) -> str:
    """Get abuse score from AbuseIPDB data."""
    if not abuse_data:
        return ""
    
    score = abuse_data.get('abuseConfidenceScore', 0)
    if score > 50:
        icon = "🦠"  # High risk
        text = f"REP{score}"
    elif score > 0:
        icon = "⚠️"  # Medium risk
        text = f"REP{score}"
    else:
        icon = "✅"  # Clean
        text = f"REP{score}"
    
    display_mode = config.get('display_mode', 'icons')
    if display_mode == 'icons':
        return f"{icon} {score}"
    else:
        # Apply color to text if available
        if config.get('text_colors', {}).get('abuse'):
            color = config['text_colors']['abuse']
            return f"\033[{_get_color_code(color)}m{text}\033[0m"
        return text

def get_firewall_status(config: Dict[str, Any]) -> str:
    """
    Check firewall status across different platforms.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Status display string or empty string if not available
    """
    checker = PlatformSecurityChecker(config)
    return checker.check_firewall_status()

def get_ssh_agent_status(config: Dict[str, Any]) -> str:
    """Check if SSH agent has loaded keys."""
    if not os.getenv("SSH_AUTH_SOCK"):
        return ""
    try:
        result = subprocess.run(['ssh-add', '-l'], capture_output=True, text=True, timeout=1, check=True)
        if result.stdout.strip():
            return get_status_display("🔑", "SSH+", config, "ssh")
    except Exception:
        pass
    return ""

def get_bitwarden_status(config: Dict[str, Any]) -> str:
    """Check if Bitwarden CLI is logged in."""
    try:
        result = subprocess.run(['bw', 'status'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            import json
            status = json.loads(result.stdout)
            if status.get('status') == 'unlocked':
                return get_status_display("🔐", "BW+", config, "bitwarden")
            elif status.get('status') == 'locked':
                return get_status_display("🔒", "BW-", config, "bitwarden")
    except Exception:
        pass
    return ""

def get_antivirus_status(config: Dict[str, Any]) -> str:
    """
    Check antivirus status across different platforms.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Status display string or empty string if not available
    """
    checker = PlatformSecurityChecker(config)
    return checker.check_antivirus_status()

def get_privacy_status(config: Dict[str, Any]) -> str:
    """
    Check privacy-related settings across different platforms.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Status display string or empty string if not available
    """
    checker = PlatformSecurityChecker(config)
    return checker.check_privacy_status()

def get_network_security_status(config: Dict[str, Any]) -> str:
    """
    Check network security indicators across different platforms.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Status display string or empty string if not available
    """
    checker = NetworkStatusChecker(config)
    return checker.check_network_security_status()

def get_system_integrity_status(config: Dict[str, Any]) -> str:
    """
    Check system integrity protection status across different platforms.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Status display string or empty string if not available
    """
    checker = PlatformSecurityChecker(config)
    return checker.check_system_integrity_status()

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

    # Get VPN status first for location formatting
    vpn_status = get_nordvpn_status(config)
    
    # Collect all status components (local statuses are always live)
    status_components = {
        "firewall": get_firewall_status(config),
        "vpn": vpn_status,
        "ssh": get_ssh_agent_status(config),
        "aws": get_aws_status(config),
        "bitwarden": get_bitwarden_status(config),
        "antivirus": get_antivirus_status(config),
        "privacy": get_privacy_status(config),
        "network_security": get_network_security_status(config),
        "system_integrity": get_system_integrity_status(config),
        "location": format_location(ip_data, config, vpn_status),
        "ip": f"({mask_ip_address(ip_data.get('ip'))})" if ip_data else "",
        "timezone": get_timezone_status(ip_data),
        "asn": get_asn_status(ip_data),
        "whois": get_whois_status(ip_data),
        "abuse": get_abuse_status(abuse_data, config),
    }

    parts = [
        f"{status_components['firewall']}" if status_components['firewall'] else None,
        f"{status_components['vpn']}" if status_components['vpn'] else None,
        f"{status_components['ssh']}" if status_components['ssh'] else None,
        f"{status_components['aws']}" if status_components['aws'] else None,
        f"{status_components['bitwarden']}" if status_components['bitwarden'] else None,
        f"{status_components['antivirus']}" if status_components['antivirus'] else None,
        f"{status_components['privacy']}" if status_components['privacy'] else None,
        f"{status_components['network_security']}" if status_components['network_security'] else None,
        f"{status_components['system_integrity']}" if status_components['system_integrity'] else None,
        f"{status_components['abuse']}" if status_components['abuse'] else None,
        f"{status_components['location']}" if status_components['location'] else None,
        #f"{status_components['asn']}" if status_components['asn'] else None,
        #f"{status_components['whois']}" if status_components['whois'] else None,
        #f"{status_components['timezone']}" if status_components['timezone'] else None,
    ]
    
    print(" ".join(filter(None, parts)))

def main() -> None:
    """Main entry point for the script's command-line interface (CLI)."""
    import argparse

    parser = argparse.ArgumentParser(prog="starship_manager.py", description="Starship prompt manager with dynamic status and system information")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("prompt", help="Print prompt data to stdout")
    subparsers.add_parser("update_cache", help="Update the local cache")

    args = parser.parse_args()

    config = load_config()
    logger = setup_logging(config)

    if args.command == "prompt":
        handle_prompt(config, logger)
    elif args.command == "update_cache":
        handle_update_cache(config, logger)
    else:
        parser.error("Unknown command")

if __name__ == "__main__":
    main()
