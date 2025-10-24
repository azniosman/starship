# Starship Prompt Customization

This project is for configuring and personalizing the [Starship prompt](https://starship.rs) for various development environments. The goal is to improve shell productivity, add dynamic status segments, and ensure the prompt works seamlessly across multiple shells like Bash, Zsh, and Fish.

## Overview

![Starship Prompt](warp-screenshot.png)

The primary goal of this project is to create a customized Starship prompt that is both aesthetically pleasing and functional. This includes:

*   **Improving shell productivity:** By providing essential information at a glance.
*   **Adding dynamic status segments:** To display relevant context-aware information.
*   **Ensuring cross-shell compatibility:** For a consistent experience across different shells.

## Tech Stack

![Bash](https://img.shields.io/badge/Shell-Bash-blue)
![Zsh](https://img.shields.io/badge/Shell-Zsh-blue)
![Fish](https://img.shields.io/badge/Shell-Fish-blue)
![Starship](https://img.shields.io/badge/Prompt%20Engine-Starship-red)
![Python](https://img.shields.io/badge/Language-Python-yellow)
![Rust](https://img.shields.io/badge/Language-Rust-orange)
![Node.js](https://img.shields.io/badge/Language-Node.js-green)

## Project Structure

*   `starship.toml`: The main configuration file for the prompt.
*   `starship_manager.py`: A Python script to fetch and display dynamic information in the prompt.
*   `ip_config.json`: Configuration file for the `starship_manager.py` script.
*   `modules/`: An optional directory for custom Starship modules and scripts.
*   `.config/fish/functions/`: For Fish shell helper functions.
*   `.config/starship_prompts/`: To store alternate prompt layouts.

## Features

The `starship_manager.py` script provides comprehensive security and system monitoring with the following features:

### 🌐 **Network & Location**
*   **Public IP Information:** Fetches public IP information from multiple services (ipinfo.io, ip-api.com, ipify, ifconfig.co).
*   **IP Reputation:** Fetches abuse score for an IP from AbuseIPDB.com with risk assessment.
*   **Location Display:** Shows country flag and city/location information.
*   **IP Masking:** Masks the last octet of the IP address for privacy (IPv4 and IPv6 supported).

### 🔒 **Security Status Indicators**
*   **Firewall Status:** 
    - Little Snitch detection (macOS)
    - pfctl status (macOS) 
    - UFW status (Linux)
*   **VPN Status:** NordVPN connection monitoring
*   **Antivirus Status:** 
    - Intego antivirus detection (macOS)
    - ClamAV detection
    - Built-in XProtect detection
*   **System Integrity:** System Integrity Protection (SIP) status
*   **Network Security:** VPN tunnel detection and network monitoring
*   **Privacy Controls:** Camera/microphone access restrictions monitoring
*   **SSH Agent:** SSH key status monitoring
*   **Password Manager:** Bitwarden CLI status (locked/unlocked)
*   **Cloud Services:** AWS profile/vault status

### 🎨 **Display Modes & Customization**
*   **Dual Display Modes:** 
    - **Icons Mode:** Visual emoji indicators (🛡️ 🔒 🛡️ 🌐 🔐)
    - **Text Mode:** Abbreviated text indicators (FW+ VPN- AV+ NET+ SIP+)
*   **Color Support:** Each status indicator can have custom colors in text mode
*   **Status Indicators:** 
    - `+` = Active/Enabled/Connected/Unlocked
    - `-` = Inactive/Disabled/Disconnected/Locked
*   **Configuration Validation:** Automatic validation of configuration values with sensible defaults

### ⚡ **Performance & Reliability**
*   **Caching:** Caches the fetched data to avoid rate limiting and improve performance.
*   **Concurrent Processing:** Multiple API calls run in parallel for faster response.
*   **Retry Logic:** Exponential backoff with jitter for network resilience.
*   **Schema Versioning:** Cache invalidation on configuration changes.
*   **Timeout Management:** Aggressive timeouts prevent prompt stalls.

## Key Commands

*   `starship init bash|zsh|fish`: Initializes Starship for the specified shell.
*   `cp ./starship.toml ~/.config/starship.toml`: Applies your custom configuration.
*   **Switching prompt layouts (optional):**
    *   **Fish example:** `prompt minimal`

## Customization Conventions

*   **Style:** Keep the prompt minimal and fast, favoring a single line.
*   **Segment Order:** Prioritize directory, git status/branch, and language version.
*   **Unicode and Color:** Use Unicode symbols and distinctive colors for better visibility.
*   **Right Prompt:** Use the right-aligned prompt sparingly for information like battery, time, or exit status.
*   **Cross-shell:** Verify all configurations on the targeted shells.

## Installation

1.  **Install Starship:**
    ```bash
    curl -sS https://starship.rs/install.sh | sh
    ```
2.  **Clone the repository:**
    ```bash
    git clone https://github.com/azniosman/starship.git ~/.config/starship
    ```
3.  **Initialize Starship for your shell:**
    *   **Bash:** Add the following to the end of your `~/.bashrc`:
        ```bash
        eval "$(starship init bash)"
        ```
    *   **Zsh:** Add the following to the end of your `~/.zshrc`:
        ```bash
        eval "$(starship init zsh)"
        ```
    *   **Fish:** Add the following to the end of your `~/.config/fish/config.fish`:
        ```fish
        starship init fish | source
        ```
4.  **Apply the configuration:**
    ```bash
    cp ~/.config/starship/starship.toml ~/.config/starship.toml
    ```

## Configuration

### 🔑 **API Keys**

To use the AbuseIPDB integration, you need to set the `ABUSEIPDB_API_KEY` environment variable to your AbuseIPDB API key.

Add the following to your shell's configuration file (e.g., `~/.bashrc`, `~/.zshrc`):

```bash
export ABUSEIPDB_API_KEY="your_api_key"
```

### ⚙️ **Display Modes**

Configure display mode in `ip_config.json`:

```json
{
  "display_mode": "icons"  // or "text"
}
```

**Icons Mode Example:**
```
🛡️ 🔓 🛡️ 🌐 🔐 🇳🇴 Oslo (45.14.193.x) ✅ 0
```

**Text Mode Example:**
```
FW+ VPN- AV+ NET+ SIP+ 🇳🇴 Oslo (45.14.193.x) REP0
```

### 🎨 **Color Customization**

Customize colors for text mode indicators:

```json
{
  "display_mode": "text",
  "text_colors": {
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
}
```

**Available Colors:** `black`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `white`, `bright_black`, `bright_red`, `bright_green`, `bright_yellow`, `bright_blue`, `bright_magenta`, `bright_cyan`, `bright_white`, `orange`, `purple`

### 📋 **Complete Configuration Options**

```json
{
  "display_mode": "icons",
  "cache_expiry": 600,
  "timeout": 3,
  "max_retries": 3,
  "abuseipdb_enabled": true,
  "text_colors": {
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
  },
  "logging": {
    "enabled": true,
    "level": "INFO",
    "log_file": "~/.cache/starship/ip_location.log"
  }
}
```

## Usage

Once installed, your prompt will be customized according to the `starship.toml` file. You can further customize the prompt by editing this file.

### `starship_manager.py` Usage

The `starship_manager.py` script provides comprehensive security and system monitoring. It has two main commands:

*   `prompt`: Fetches and displays security status information.
*   `update_cache`: Updates the cache with the latest information.

To use the script, add the following to your `starship.toml` file:

```toml
[custom.prompt]
command = "python ~/.config/starship/starship_manager.py prompt"
when = true
format = "[$output]($style) "
style = "bold #83a598"
```

### 🔄 **Background Cache Updates**

Run the cache update command periodically to keep data fresh:

```bash
python ~/.config/starship/starship_manager.py update_cache
```

**Recommended:** Add to your shell startup (e.g., `~/.zshrc`):
```bash
python ~/.config/starship/starship_manager.py update_cache &|
```

### 📊 **Status Indicators Reference**

| **Indicator** | **Icon** | **Text** | **Description** |
|---------------|----------|----------|-----------------|
| Firewall (active) | `🛡️` | `FW+` | Little Snitch/pfctl/UFW active |
| Firewall (inactive) | `🚫` | `FW-` | Firewall disabled |
| VPN (connected) | `🔒` | `VPN+` | NordVPN connected |
| VPN (disconnected) | `🔓` | `VPN-` | NordVPN disconnected |
| Antivirus (active) | `🛡️` | `AV+` | Intego/ClamAV/XProtect |
| Network Security | `🌐` | `NET+` | VPN routes detected |
| System Integrity (enabled) | `🔐` | `SIP+` | SIP enabled |
| System Integrity (disabled) | `⚠️` | `SIP-` | SIP disabled |
| Bitwarden (unlocked) | `🔐` | `BW+` | Bitwarden unlocked |
| Bitwarden (locked) | `🔒` | `BW-` | Bitwarden locked |
| SSH Agent | `🔑` | `SSH+` | SSH keys loaded |
| AWS | `☁️` | `AWS+` | AWS profile active |
| Privacy | `🔒` | `PRIV+` | Privacy controls active |
| IP Reputation | `✅` | `REP0` | Clean abuse score |

## Performance

*   **Concurrent lookups:** Public IP is fetched from multiple services in parallel.
*   **Retries with backoff:** Transient network errors are retried with exponential backoff and jitter.
*   **Aggressive timeouts:** Short per-call timeouts prevent prompt stalls.
*   **Cache schema:** Local cache includes `schema_version` for safe invalidation on upgrades.

## Privacy

*   **IP masking:** IPv4/IPv6 are masked in the prompt output (last segment replaced).
*   **Redacted logs:** Logs avoid writing raw IPs in error messages.
*   **Optional AbuseIPDB:** You can disable checks by setting `"abuseipdb_enabled": false` in `ip_config.json`.

## Troubleshooting

### 🔧 **Common Issues**

*   **Firewall Detection:** 
    - Little Snitch: Ensure the application is running
    - pfctl: May require permissions on macOS
    - UFW: Ensure firewall is installed on Linux
*   **VPN Status:** If `nordvpn` CLI is not installed, VPN segment will show as disconnected
*   **Antivirus Detection:** 
    - Intego: Ensure the application is running
    - ClamAV: Install `clamav` package
    - XProtect: Built-in macOS protection
*   **Bitwarden CLI:** Install `bw` CLI tool and ensure you're logged in
*   **SSH Agent:** Ensure `SSH_AUTH_SOCK` environment variable is set
*   **API Keys:** Verify `ABUSEIPDB_API_KEY` environment variable is set correctly

### 🐛 **Technical Issues**

*   **Python Path:** Ensure the `command` path in `starship.toml` is correct and executable
*   **Stale Cache:** Delete `~/.cache/starship/prompt_data.json` if data seems outdated; it will be recreated
*   **Color Display:** Ensure your terminal supports ANSI color codes for text mode colors
*   **Permissions:** Some system checks may require elevated permissions
*   **Network Issues:** Check internet connectivity for IP and abuse score fetching

### 📝 **Debugging**

Enable logging in `ip_config.json`:

```json
{
  "logging": {
    "enabled": true,
    "level": "DEBUG",
    "log_file": "~/.cache/starship/ip_location.log"
  }
}
```

Check the log file for detailed error information.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License.
