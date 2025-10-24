#!/usr/bin/env python3
"""
Platform-specific utilities for starship_manager.py

This module abstracts platform-specific functionality to improve maintainability
and make it easier to add support for new platforms.
"""

import sys
from typing import Optional, Dict, Any
from starship_constants import PlatformDetector, StatusIcons
from starship_security import SecurityChecker


class PlatformSecurityChecker:
    """Platform-specific security status checking."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.security_checker = SecurityChecker(config)
    
    def check_firewall_status(self) -> str:
        """Check firewall status based on platform."""
        if PlatformDetector.is_macos():
            return self._check_macos_firewall()
        elif PlatformDetector.is_linux():
            return self._check_linux_firewall()
        else:
            return ""
    
    def check_antivirus_status(self) -> str:
        """Check antivirus status based on platform."""
        if PlatformDetector.is_macos():
            return self._check_macos_antivirus()
        elif PlatformDetector.is_linux():
            return self._check_linux_antivirus()
        else:
            return ""
    
    def check_system_integrity_status(self) -> str:
        """Check system integrity protection status."""
        if PlatformDetector.is_macos():
            return self._check_macos_sip()
        else:
            return ""
    
    def check_privacy_status(self) -> str:
        """Check privacy-related settings."""
        if PlatformDetector.is_macos():
            return self._check_macos_privacy()
        else:
            return ""
    
    def _check_macos_firewall(self) -> str:
        """Check firewall status on macOS."""
        try:
            # Check for Little Snitch first
            if self.security_checker.check_little_snitch():
                return self._get_status_display(
                    StatusIcons.FIREWALL_ACTIVE, 
                    StatusIcons.FIREWALL_TEXT_ACTIVE, 
                    "firewall"
                )
            
            # Fallback to pfctl
            pfctl_output = self.security_checker.check_pfctl_status()
            if pfctl_output and "Status: Enabled" in pfctl_output:
                return self._get_status_display(
                    StatusIcons.FIREWALL_ACTIVE, 
                    StatusIcons.FIREWALL_TEXT_ACTIVE, 
                    "firewall"
                )
            else:
                return self._get_status_display(
                    StatusIcons.FIREWALL_INACTIVE, 
                    StatusIcons.FIREWALL_TEXT_INACTIVE, 
                    "firewall"
                )
        except Exception:
            pass
        return ""
    
    def _check_linux_firewall(self) -> str:
        """Check firewall status on Linux."""
        try:
            ufw_output = self.security_checker.check_ufw_status()
            if ufw_output and "Status: active" in ufw_output:
                return self._get_status_display(
                    StatusIcons.FIREWALL_ACTIVE, 
                    StatusIcons.FIREWALL_TEXT_ACTIVE, 
                    "firewall"
                )
            else:
                return self._get_status_display(
                    StatusIcons.FIREWALL_INACTIVE, 
                    StatusIcons.FIREWALL_TEXT_INACTIVE, 
                    "firewall"
                )
        except Exception:
            pass
        return ""
    
    def _check_macos_antivirus(self) -> str:
        """Check antivirus status on macOS."""
        try:
            # Check for Intego antivirus
            if self.security_checker.check_intego_process():
                return self._get_status_display(
                    StatusIcons.ANTIVIRUS_ACTIVE, 
                    StatusIcons.ANTIVIRUS_TEXT_ACTIVE, 
                    "antivirus"
                )
            
            # Check for Intego in Applications
            if self.security_checker.check_intego_installation():
                return self._get_status_display(
                    StatusIcons.ANTIVIRUS_ACTIVE, 
                    StatusIcons.ANTIVIRUS_TEXT_ACTIVE, 
                    "antivirus"
                )
            
            # Fallback: Check for ClamAV
            if self.security_checker.check_clamav():
                return self._get_status_display(
                    StatusIcons.ANTIVIRUS_CLAMAV, 
                    StatusIcons.ANTIVIRUS_TEXT_ACTIVE, 
                    "antivirus"
                )
            
            # Fallback: Check for built-in XProtect
            if self.security_checker.check_xprotect():
                return self._get_status_display(
                    StatusIcons.ANTIVIRUS_ACTIVE, 
                    StatusIcons.ANTIVIRUS_TEXT_ACTIVE, 
                    "antivirus"
                )
        except Exception:
            pass
        return ""
    
    def _check_linux_antivirus(self) -> str:
        """Check antivirus status on Linux."""
        try:
            # Check for ClamAV
            if self.security_checker.check_clamav():
                return self._get_status_display(
                    StatusIcons.ANTIVIRUS_CLAMAV, 
                    StatusIcons.ANTIVIRUS_TEXT_ACTIVE, 
                    "antivirus"
                )
        except Exception:
            pass
        return ""
    
    def _check_macos_sip(self) -> str:
        """Check System Integrity Protection status on macOS."""
        try:
            csrutil_output = self.security_checker.check_csrutil_status()
            if csrutil_output:
                if 'enabled' in csrutil_output.lower():
                    return self._get_status_display(
                        StatusIcons.SYSTEM_INTEGRITY_ENABLED, 
                        StatusIcons.SYSTEM_INTEGRITY_TEXT_ENABLED, 
                        "system_integrity"
                    )
                else:
                    return self._get_status_display(
                        StatusIcons.SYSTEM_INTEGRITY_DISABLED, 
                        StatusIcons.SYSTEM_INTEGRITY_TEXT_DISABLED, 
                        "system_integrity"
                    )
        except Exception:
            pass
        return ""
    
    def _check_macos_privacy(self) -> str:
        """Check privacy-related settings on macOS."""
        try:
            # Note: This would need to be implemented with secure subprocess calls
            # For now, we'll skip this check as it requires database access
            pass
        except Exception:
            pass
        return ""
    
    def _get_status_display(self, icon: str, text: str, status_type: str) -> str:
        """Get status display based on configuration."""
        from starship_manager import get_status_display
        return get_status_display(icon, text, self.config, status_type)