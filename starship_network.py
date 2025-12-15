#!/usr/bin/env python3
"""
Network utilities for starship_manager.py

This module handles IP information fetching, parsing, and network-related operations.
"""

import json
import time
import random
import logging
from typing import Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from starship_constants import IPServices, RetryConfig, ConfigDefaults


class IPFetcher:
    """Handles IP information fetching from multiple services."""
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger
        self.max_retries = max(0, int(config.get('max_retries', ConfigDefaults.MAX_RETRIES)))
        self.timeout = float(config.get('timeout', ConfigDefaults.TIMEOUT))
    
    def fetch_ip_info(self) -> Optional[Dict[str, Any]]:
        """
        Fetch public IP information from multiple services concurrently.
        
        Returns:
            Dictionary with IP information or None if all services fail
        """
        with ThreadPoolExecutor(max_workers=len(IPServices.SERVICES)) as executor:
            future_to_service = {
                executor.submit(self._fetch_service, svc): svc 
                for svc in IPServices.SERVICES
            }
            
            try:
                for future in as_completed(future_to_service, timeout=self.timeout + 1):
                    try:
                        result = future.result()
                        if result:
                            # Cancel remaining futures
                            for f in future_to_service:
                                if f != future and not f.done():
                                    f.cancel()
                            return result
                    except Exception as e:
                        if self.logger:
                            self.logger.warning(f"Future execution failed: {type(e).__name__}")
                        continue
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"ThreadPoolExecutor failed: {type(e).__name__}")
        
        return None
    
    def _fetch_service(self, service: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Fetch IP info from a single service with retry logic."""
        service_name = service.get('name', 'unknown')
        
        for attempt in range(self.max_retries + 1):
            try:
                result = self._make_request(service)
                if result:
                    if self.logger:
                        self.logger.info(f"Successfully fetched IP info from {service_name}")
                    return result
            except (URLError, HTTPError, json.JSONDecodeError) as e:
                if self.logger:
                    self.logger.warning(f"Service {service_name} attempt {attempt+1} failed: {type(e).__name__}")
                if attempt < self.max_retries:
                    delay = RetryConfig.calculate_backoff_delay(attempt)
                    time.sleep(delay)
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Service {service_name} attempt {attempt+1} failed: unexpected error")
                if attempt < self.max_retries:
                    time.sleep(0.25)
        
        return None
    
    def _make_request(self, service: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make HTTP request to service and parse response."""
        req = Request(service["url"], headers=IPServices.HEADERS)
        
        with urlopen(req, timeout=self.timeout) as response:
            if response.status != 200:
                return None
            
            data = json.loads(response.read().decode('utf-8'))
            
            # Import parser dynamically to avoid circular imports
            parser_name = service["parser"]
            if parser_name == "parse_ipinfo":
                from starship_manager import parse_ipinfo
                return parse_ipinfo(data)
            elif parser_name == "parse_ip_api":
                from starship_manager import parse_ip_api
                return parse_ip_api(data)
            elif parser_name == "parse_ipify":
                from starship_manager import parse_ipify
                return parse_ipify(data)
            elif parser_name == "parse_ifconfig":
                from starship_manager import parse_ifconfig
                return parse_ifconfig(data)
        
        return None


class AbuseIPDBClient:
    """Client for AbuseIPDB API."""
    
    def __init__(self, api_key: Optional[str], logger: Optional[logging.Logger] = None):
        self.api_key = api_key
        self.logger = logger
    
    def fetch_abuse_info(self, ip_address: Optional[str]) -> Optional[Dict[str, Any]]:
        """
        Fetch abuse score for an IP address.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with abuse information or None
        """
        if not self.api_key or not ip_address:
            return None
        
        # Basic IP address validation
        from starship_manager import _is_valid_ip
        if not _is_valid_ip(ip_address):
            if self.logger:
                self.logger.warning("Invalid IP address format")
            return None
        
        url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90'
        headers = {
            'Accept': 'application/json', 
            'Key': self.api_key, 
            'User-Agent': 'starship-prompt/1.0'
        }
        
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=3) as response:
                if response.status != 200:
                    if self.logger:
                        self.logger.warning(f"AbuseIPDB returned HTTP {response.status}")
                    return None
                
                data = json.loads(response.read().decode('utf-8'))
                return data.get("data", {})
        
        except (URLError, HTTPError) as e:
            if self.logger:
                self.logger.warning(f"AbuseIPDB network error: {type(e).__name__}")
        except json.JSONDecodeError:
            if self.logger:
                self.logger.warning("AbuseIPDB returned invalid JSON")
        except Exception as e:
            if self.logger:
                self.logger.warning(f"AbuseIPDB check failed: {type(e).__name__}")
        
        return None


class NetworkStatusChecker:
    """Check network-related security status."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def check_network_security_status(self) -> str:
        """Check network security indicators."""
        try:
            if sys.platform == "darwin":
                return self._check_macos_network_security()
        except Exception:
            pass
        return ""
    
    def _check_macos_network_security(self) -> str:
        """Check network security on macOS."""
        try:
            # Check for unusual network connections
            result = self._safe_subprocess_run(['netstat', '-rn'], timeout=1)
            if result and result.returncode == 0:
                # Look for VPN routes or suspicious gateways
                if 'tun' in result.stdout or 'utun' in result.stdout:
                    from starship_manager import get_status_display
                    from starship_constants import StatusIcons
                    return get_status_display(
                        StatusIcons.NETWORK_SECURITY, 
                        StatusIcons.NETWORK_SECURITY_TEXT, 
                        self.config, 
                        "network_security"
                    )
        except Exception:
            pass
        return ""
    
    def _safe_subprocess_run(self, cmd: list, timeout: int = 1):
        """Safely run subprocess with input validation."""
        try:
            if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd):
                return None
            
            import subprocess
            return subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
        except Exception:
            return None
