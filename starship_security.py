#!/usr/bin/env python3
"""
Secure subprocess utilities for starship_manager.py

This module provides secure subprocess execution with input validation,
command sanitization, and security best practices.
"""

import subprocess
import shlex
from typing import List, Optional, Union, Dict, Any
import logging


class SecureSubprocess:
    """Secure subprocess execution with input validation."""
    
    # Allowed commands for security checks
    ALLOWED_COMMANDS = {
        # Process management
        'pgrep', 'ps', 'top',
        
        # Network tools
        'netstat', 'ifconfig', 'ping', 'nslookup',
        
        # System tools
        'pfctl', 'ufw', 'csrutil', 'xattr', 'ls',
        
        # Security tools
        'clamdscan', 'ssh-add', 'bw', 'nordvpn',
        
        # Database tools
        'sqlite3',
        
        # Shell utilities
        'which', 'whereis', 'find'
    }
    
    # Dangerous commands that should never be executed
    FORBIDDEN_COMMANDS = {
        'rm', 'del', 'format', 'fdisk', 'mkfs', 'dd',
        'sudo', 'su', 'chmod', 'chown', 'passwd',
        'shutdown', 'reboot', 'halt', 'poweroff',
        'curl', 'wget', 'nc', 'netcat', 'telnet',
        'bash', 'sh', 'zsh', 'fish', 'csh', 'tcsh'
    }
    
    @classmethod
    def validate_command(cls, cmd: Union[str, List[str]]) -> bool:
        """
        Validate that a command is safe to execute.
        
        Args:
            cmd: Command string or list of command parts
            
        Returns:
            True if command is safe, False otherwise
        """
        if isinstance(cmd, str):
            # Parse command string safely
            try:
                parts = shlex.split(cmd)
            except ValueError:
                return False
        elif isinstance(cmd, list):
            parts = cmd
        else:
            return False
        
        if not parts:
            return False
        
        # Get the base command (first part)
        base_cmd = parts[0].lower()
        
        # Check if command is forbidden
        if base_cmd in cls.FORBIDDEN_COMMANDS:
            return False
        
        # Check if command is in allowed list
        if base_cmd not in cls.ALLOWED_COMMANDS:
            return False
        
        # Additional validation for specific commands
        if not cls._validate_command_args(base_cmd, parts):
            return False
        
        return True
    
    @classmethod
    def _validate_command_args(cls, base_cmd: str, parts: List[str]) -> bool:
        """
        Validate command arguments for specific commands.
        
        Args:
            base_cmd: Base command name
            parts: Full command parts
            
        Returns:
            True if arguments are safe, False otherwise
        """
        # Validate pgrep arguments
        if base_cmd == 'pgrep':
            # Only allow specific patterns
            allowed_patterns = [
                'Little Snitch', 'Intego', 'NordVPN', 'Little Snitch Agent'
            ]
            if len(parts) > 1:
                pattern = ' '.join(parts[1:])
                return any(allowed in pattern for allowed in allowed_patterns)
        
        # Validate sqlite3 arguments
        elif base_cmd == 'sqlite3':
            # Only allow specific database paths and queries
            if len(parts) < 2:
                return False
            db_path = parts[1]
            allowed_paths = [
                '/Library/Application Support/com.apple.TCC/TCC.db'
            ]
            return db_path in allowed_paths
        
        # Validate ls arguments
        elif base_cmd == 'ls':
            # Only allow specific directories
            if len(parts) > 1:
                path = parts[1]
                allowed_paths = ['/Applications']
                return path in allowed_paths
        
        # Validate xattr arguments
        elif base_cmd == 'xattr':
            # Only allow specific paths
            if len(parts) > 1:
                path = parts[1]
                allowed_paths = [
                    '/System/Library/CoreServices/XProtect.bundle'
                ]
                return path in allowed_paths
        
        return True
    
    @classmethod
    def safe_run(cls, cmd: Union[str, List[str]], **kwargs) -> Optional[subprocess.CompletedProcess]:
        """
        Safely execute a subprocess command with validation.
        
        Args:
            cmd: Command to execute (string or list)
            **kwargs: Additional arguments for subprocess.run
            
        Returns:
            CompletedProcess result or None if validation fails
            
        Raises:
            ValueError: If command fails validation
        """
        if not cls.validate_command(cmd):
            raise ValueError(f"Command failed security validation: {cmd}")
        
        # Set safe defaults
        safe_kwargs = {
            'capture_output': True,
            'text': True,
            'timeout': 5,  # Default timeout
            'check': False,  # Don't raise on non-zero exit
        }
        safe_kwargs.update(kwargs)
        
        try:
            return subprocess.run(cmd, **safe_kwargs)
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            logging.warning(f"Subprocess execution failed: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected subprocess error: {e}")
            return None


class SecurityChecker:
    """High-level security status checker with secure subprocess calls."""
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger
        self.subprocess = SecureSubprocess()
    
    def check_little_snitch(self) -> bool:
        """Check if Little Snitch is running securely."""
        try:
            result = self.subprocess.safe_run(['pgrep', '-f', 'Little Snitch'], timeout=1)
            return result and result.returncode == 0 and result.stdout.strip()
        except ValueError:
            if self.logger:
                self.logger.warning("Little Snitch check failed security validation")
            return False
    
    def check_intego_process(self) -> bool:
        """Check if Intego antivirus process is running securely."""
        try:
            result = self.subprocess.safe_run(['pgrep', '-f', 'Intego'], timeout=1)
            return result and result.returncode == 0 and result.stdout.strip()
        except ValueError:
            if self.logger:
                self.logger.warning("Intego process check failed security validation")
            return False
    
    def check_intego_installation(self) -> bool:
        """Check if Intego is installed securely."""
        try:
            result = self.subprocess.safe_run(['ls', '/Applications'], timeout=1)
            return result and result.returncode == 0 and 'Intego' in result.stdout
        except ValueError:
            if self.logger:
                self.logger.warning("Intego installation check failed security validation")
            return False
    
    def check_pfctl_status(self) -> Optional[str]:
        """Check pfctl firewall status securely."""
        try:
            result = self.subprocess.safe_run(['pfctl', '-s', 'info'], timeout=1)
            if result and result.returncode == 0:
                return result.stdout
        except ValueError:
            if self.logger:
                self.logger.warning("pfctl check failed security validation")
        return None
    
    def check_ufw_status(self) -> Optional[str]:
        """Check UFW firewall status securely."""
        try:
            result = self.subprocess.safe_run(['ufw', 'status'], timeout=1)
            if result and result.returncode == 0:
                return result.stdout
        except ValueError:
            if self.logger:
                self.logger.warning("UFW check failed security validation")
        return None
    
    def check_csrutil_status(self) -> Optional[str]:
        """Check System Integrity Protection status securely."""
        try:
            result = self.subprocess.safe_run(['csrutil', 'status'], timeout=1)
            if result and result.returncode == 0:
                return result.stdout
        except ValueError:
            if self.logger:
                self.logger.warning("csrutil check failed security validation")
        return None
    
    def check_xprotect(self) -> bool:
        """Check XProtect availability securely."""
        try:
            result = self.subprocess.safe_run([
                'xattr', '-l', '/System/Library/CoreServices/XProtect.bundle'
            ], timeout=1)
            return result and result.returncode == 0
        except ValueError:
            if self.logger:
                self.logger.warning("XProtect check failed security validation")
            return False
    
    def check_clamav(self) -> bool:
        """Check ClamAV availability securely."""
        try:
            result = self.subprocess.safe_run(['clamdscan', '--version'], timeout=1)
            return result and result.returncode == 0
        except ValueError:
            if self.logger:
                self.logger.warning("ClamAV check failed security validation")
            return False
    
    def check_ssh_keys(self) -> Optional[str]:
        """Check SSH agent keys securely."""
        try:
            result = self.subprocess.safe_run(['ssh-add', '-l'], timeout=1)
            if result and result.returncode == 0:
                return result.stdout
        except ValueError:
            if self.logger:
                self.logger.warning("SSH agent check failed security validation")
        return None
    
    def check_bitwarden_status(self) -> Optional[str]:
        """Check Bitwarden CLI status securely."""
        try:
            result = self.subprocess.safe_run(['bw', 'status'], timeout=2)
            if result and result.returncode == 0:
                return result.stdout
        except ValueError:
            if self.logger:
                self.logger.warning("Bitwarden check failed security validation")
        return None
    
    def check_nordvpn_status(self) -> Optional[str]:
        """Check NordVPN status securely."""
        try:
            result = self.subprocess.safe_run(['nordvpn', 'status'], timeout=2)
            if result and result.returncode == 0:
                return result.stdout
        except ValueError:
            if self.logger:
                self.logger.warning("NordVPN check failed security validation")
        return None
    
    def check_network_routes(self) -> Optional[str]:
        """Check network routes securely."""
        try:
            result = self.subprocess.safe_run(['netstat', '-rn'], timeout=1)
            if result and result.returncode == 0:
                return result.stdout
        except ValueError:
            if self.logger:
                self.logger.warning("Network routes check failed security validation")
        return None
