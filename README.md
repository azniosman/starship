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

The `starship_manager.py` script provides the following features:

*   **Public IP Information:** Fetches public IP information from multiple services (ipinfo.io, ip-api.com).
*   **Abuse Score:** Fetches abuse score for an IP from AbuseIPDB.com.
*   **Caching:** Caches the fetched data to avoid rate limiting and improve performance.
*   **Status Indicators:** Provides status indicators for:
    *   NordVPN connection status.
    *   AWS profile/vault existence.
    *   Timezone.
    *   ASN (Autonomous System Number).
    *   WHOIS information.
    *   AbuseIPDB score.
    *   Firewall status (UFW for Linux, pfctl for macOS).
    *   SSH agent status.
*   **IP Masking:** Masks the last octet of the IP address for privacy (IPv4 and IPv6 supported).
*   **Country Flag:** Converts country code to a flag emoji.
*   **Animated Banner:** Displays an animated "It's Warp Time!" banner with customizable typewriter effects, colors, and timing.
*   **CLI:** Provides a CLI to either print the prompt, update the cache, or display the banner.

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

To use the AbuseIPDB integration, you need to set the `ABUSEIPDB_API_KEY` environment variable to your AbuseIPDB API key.

You can add the following to your shell's configuration file (e.g., `~/.bashrc`, `~/.zshrc`):

```bash
export ABUSEIPDB_API_KEY="your_api_key"
```

Optional `ip_config.json` overrides (deep-merged with defaults):

```json
{
  "cache_expiry": 900,
  "timeout": 2.0,
  "max_retries": 2,
  "abuseipdb_enabled": false,
  "logging": {
    "enabled": true,
    "level": "INFO",
    "log_file": "~/.cache/starship/ip_location.log"
  },
  "banner_animation": {
    "enabled": true,
    "char_delay": 0.001,
    "line_delay": 0.05,
    "colors": ["bright_blue", "cyan", "bright_cyan", "blue"]
  }
}
```

## Usage

Once installed, your prompt will be customized according to the `starship.toml` file. You can further customize the prompt by editing this file.

### `starship_manager.py` Usage

The `starship_manager.py` script can be used to display dynamic information in the prompt. It has three commands:

*   `prompt`: Fetches and displays the prompt information.
*   `update_cache`: Updates the cache with the latest information.
*   `banner`: Displays the animated "It's Warp Time!" banner.

To use the script, you can add the following to your `starship.toml` file:

```toml
[custom.location_status]
command = "python /absolute/path/to/starship_manager.py prompt"
when = "true"
format = "$output"
```

You can also run the `update_cache` command periodically to keep the cache up to date:

```bash
python /path/to/starship_manager.py update_cache
```

### Animated Banner

The script includes an animated banner feature that displays "It's Warp Time!" with customizable effects:

```bash
python /path/to/starship_manager.py banner
```

**Features:**
*   **Typewriter Effect:** Characters appear one by one with customizable timing
*   **Multi-color Support:** Each line can have different colors that cycle through
*   **Pulse Effect:** Final pulsing border effect after animation completes
*   **Graceful Fallbacks:** Works with or without rich library, with static fallback option

**Banner Animation Configuration:**

Add the following to your `ip_config.json` to customize the banner animation:

```json
{
  "banner_animation": {
    "enabled": true,              // Enable/disable animation
    "char_delay": 0.001,          // Delay between characters (seconds)
    "line_delay": 0.05,           // Delay between lines (seconds)
    "colors": [                   // Colors cycle through each line
      "bright_blue",
      "cyan",
      "bright_cyan",
      "blue"
    ]
  }
}
```

**Available Colors:** `black`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `white`, `bright_black`, `bright_red`, `bright_green`, `bright_yellow`, `bright_blue`, `bright_magenta`, `bright_cyan`, `bright_white`

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

*   **Firewall on macOS:** `pfctl -s info` may require permissions. If empty, run the prompt without that segment or enable the firewall.
*   **NordVPN missing:** If `nordvpn` CLI is not installed, the VPN segment will show as unlocked.
*   **Python path:** Ensure the `command` path in `starship.toml` is correct and executable.
*   **Stale cache:** Delete `~/.cache/starship/prompt_data.json` if data seems outdated; it will be recreated.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License.
