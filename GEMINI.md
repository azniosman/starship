# Project Context: Starship Prompt Customization

## 1. Project Overview
- **Goal:** This project is for configuring and customizing the Starship prompt for my development environment.
- **Starship:** A fast, minimal, and highly customizable cross-shell prompt (https://starship.rs).
- **Key Outcomes:** Improve shell productivity, add dynamic status segments, ensure the prompt works for multiple shells (Bash, Zsh, Fish).

## 2. Tech Stack
- **Shells:** Bash, Zsh, Fish (others if needed)
- **Prompt Engine:** starship (TOML-based config)
- **Languages (optional for custom modules):** Rust, Node.js, shell scripts

## 3. Project Structure
- `starship.toml` — main configuration file for the prompt
- `modules/` — optional directory for custom Starship modules/scripts
- `.config/fish/functions/` — Fish shell helper functions (if needed)
- `.config/starship_prompts/` — alternate prompt layouts

## 4. Key Commands
- `starship init bash|zsh|fish` — initialize Starship for the shell
- `cp ./starship.toml ~/.config/starship.toml` — apply your config
- (Optional) Shell function for switching prompt layouts:
  - Fish example: `prompt minimal` (see function in project)

## 5. Customization Conventions
- **Style:** Keep the prompt minimal and fast; favor a single line unless multi-line info is critical.
- **Segment Order:** Place directory, git status/branch, and language version early for visibility.
- **Unicode and Color:** Use Unicode symbols and distinctive colors for visibility (see Starship docs).
- **Right Prompt:** Use right-aligned info sparingly—battery, time, or exit status.
- **Cross-shell:** Verify all configs on targeted shells.

## 6. Current Goals
- **Short-term:** Polish the main `starship.toml` to visually balance info and aesthetics.
- **Next:** Implement and test prompt switching function for Fish shell.

## 7. References
- [Starship Docs](https://starship.rs/config/)
- [Starship Module List](https://starship.rs/config/#prompt)
- Example custom segment: `[custom.tailwind]` for Tailwind CSS detection