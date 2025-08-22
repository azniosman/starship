# Starship Prompt Customization

This project is for configuring and personalizing the [Starship prompt](https://starship.rs) for various development environments. The goal is to improve shell productivity, add dynamic status segments, and ensure the prompt works seamlessly across multiple shells like Bash, Zsh, and Fish.

## Overview

The primary goal of this project is to create a customized Starship prompt that is both aesthetically pleasing and functional. This includes:

*   **Improving shell productivity:** By providing essential information at a glance.
*   **Adding dynamic status segments:** To display relevant context-aware information.
*   **Ensuring cross-shell compatibility:** For a consistent experience across different shells.

## Tech Stack

*   **Shells:** Bash, Zsh, Fish
*   **Prompt Engine:** [Starship](https://starship.rs) (TOML-based config)
*   **Languages (for custom modules):** Rust, Node.js, shell scripts

## Project Structure

*   `starship.toml`: The main configuration file for the prompt.
*   `modules/`: An optional directory for custom Starship modules and scripts.
*   `.config/fish/functions/`: For Fish shell helper functions.
*   `.config/starship_prompts/`: To store alternate prompt layouts.

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

## Usage

Once installed, your prompt will be customized according to the `starship.toml` file. You can further customize the prompt by editing this file.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License.
