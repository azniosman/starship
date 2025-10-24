#!/usr/bin/env python3
"""
Constants and configuration management for starship_manager.py

This module contains all constants, default configurations, and helper classes
to improve code organization and maintainability.
"""

from typing import Dict, Any, List, Optional
import sys


class ConfigDefaults:
    """Default configuration values."""
    
    # Cache settings
    CACHE_EXPIRY = 600  # 10 minutes
    CACHE_DIR = "~/.cache/starship"
    
    # Network settings
    TIMEOUT = 3
    MAX_RETRIES = 3
    
    # API settings
    ABUSEIPDB_ENABLED = True
    
    # Display settings
    DISPLAY_MODE = "icons"
    MAX_ORG_LENGTH = 20
    
    # Schema version for cache invalidation
    SCHEMA_VERSION = 1
    
    # Default text colors
    DEFAULT_TEXT_COLORS = {
        "firewall": "green",
        "vpn": "blue", 
        "antivirus": "yellow",
        "network_security": "cyan",
        "system_integrity": "magenta",
        "bitwarden": "red",
        "ssh": "white",
        "aws": "orange",
        "privacy": "purple",
        "abuse": "bright_green"
    }
    
    # Default logging configuration
    DEFAULT_LOGGING = {
        "enabled": False,
        "level": "INFO",
        "log_file": "~/.cache/starship/ip_location.log"
    }


class StatusIcons:
    """Status indicator icons and text."""
    
    # Firewall
    FIREWALL_ACTIVE = "🛡️"
    FIREWALL_INACTIVE = "🚫"
    FIREWALL_TEXT_ACTIVE = "FW+"
    FIREWALL_TEXT_INACTIVE = "FW-"
    
    # VPN
    VPN_CONNECTED = "🔒"
    VPN_DISCONNECTED = "🔓"
    VPN_TEXT_CONNECTED = "VPN+"
    VPN_TEXT_DISCONNECTED = "VPN-"
    
    # Antivirus
    ANTIVIRUS_ACTIVE = "🛡️"
    ANTIVIRUS_CLAMAV = "🦠"
    ANTIVIRUS_TEXT_ACTIVE = "AV+"
    
    # Network Security
    NETWORK_SECURITY = "🌐"
    NETWORK_SECURITY_TEXT = "NET+"
    
    # System Integrity
    SYSTEM_INTEGRITY_ENABLED = "🔐"
    SYSTEM_INTEGRITY_DISABLED = "⚠️"
    SYSTEM_INTEGRITY_TEXT_ENABLED = "SIP+"
    SYSTEM_INTEGRITY_TEXT_DISABLED = "SIP-"
    
    # Bitwarden
    BITWARDEN_UNLOCKED = "🔐"
    BITWARDEN_LOCKED = "🔒"
    BITWARDEN_TEXT_UNLOCKED = "BW+"
    BITWARDEN_TEXT_LOCKED = "BW-"
    
    # SSH
    SSH_ACTIVE = "🔑"
    SSH_TEXT_ACTIVE = "SSH+"
    
    # AWS
    AWS_ACTIVE = "☁️"
    AWS_TEXT_ACTIVE = "AWS+"
    
    # Privacy
    PRIVACY_ACTIVE = "🔒"
    PRIVACY_TEXT_ACTIVE = "PRIV+"
    
    # Abuse/Reputation
    ABUSE_CLEAN = "✅"
    ABUSE_MEDIUM = "⚠️"
    ABUSE_HIGH = "🦠"
    
    # General
    OFFLINE = "🔌 offline"
    WORLD = "🌐"


class IPServices:
    """IP service configurations."""
    
    SERVICES = [
        {
            "name": "ipinfo.io",
            "url": "https://ipinfo.io/json",
            "parser": "parse_ipinfo"
        },
        {
            "name": "ip-api.com",
            "url": "https://ip-api.com/json?fields=status,message,countryCode,city,regionName,org,as,query,timezone",
            "parser": "parse_ip_api"
        },
        {
            "name": "ipify",
            "url": "https://api.ipify.org?format=json",
            "parser": "parse_ipify"
        },
        {
            "name": "ifconfig.co",
            "url": "https://ifconfig.co/json",
            "parser": "parse_ifconfig"
        }
    ]
    
    HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; starship-prompt/1.0)'}


class PlatformDetector:
    """Platform detection utilities."""
    
    @staticmethod
    def is_macos() -> bool:
        """Check if running on macOS."""
        return sys.platform == "darwin"
    
    @staticmethod
    def is_linux() -> bool:
        """Check if running on Linux."""
        return sys.platform == "linux"
    
    @staticmethod
    def is_windows() -> bool:
        """Check if running on Windows."""
        return sys.platform == "win32"


class RetryConfig:
    """Retry configuration and utilities."""
    
    @staticmethod
    def calculate_backoff_delay(attempt: int, base_delay: float = 0.25, max_delay: float = 2.5) -> float:
        """
        Calculate exponential backoff delay with jitter.
        
        Args:
            attempt: Current attempt number (0-based)
            base_delay: Base delay in seconds
            max_delay: Maximum delay in seconds
            
        Returns:
            Delay in seconds
        """
        import random
        delay = min(2.0 ** attempt * base_delay + random.uniform(0, base_delay), max_delay)
        return delay


class ValidationRules:
    """Configuration validation rules."""
    
    VALID_LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    VALID_DISPLAY_MODES = ['icons', 'text']
    
    @staticmethod
    def is_valid_log_level(level: str) -> bool:
        """Check if log level is valid."""
        return level.upper() in ValidationRules.VALID_LOG_LEVELS
    
    @staticmethod
    def is_valid_display_mode(mode: str) -> bool:
        """Check if display mode is valid."""
        return mode in ValidationRules.VALID_DISPLAY_MODES
    
    @staticmethod
    def is_positive_number(value: Any) -> bool:
        """Check if value is a positive number."""
        return isinstance(value, (int, float)) and value > 0
    
    @staticmethod
    def is_non_negative_integer(value: Any) -> bool:
        """Check if value is a non-negative integer."""
        return isinstance(value, int) and value >= 0
