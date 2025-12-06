"""Utilities for retrieving theme-aware UI color tokens."""

from dataclasses import dataclass

from theme import (
    PROXMOX_ACCENT,
    PROXMOX_DARK,
    PROXMOX_LIGHT,
    PROXMOX_MEDIUM,
    PROXMOX_ORANGE,
    theme_color,
)


@dataclass(frozen=True)
class UIColorTokens:
    app_bg: str
    card_bg: str
    card_border: str
    input_bg: str
    input_border: str
    input_border_subtle: str
    input_active_bg: str
    button_primary_bg: str
    button_primary_active_bg: str
    button_secondary_bg: str
    button_secondary_active_bg: str
    button_success_bg: str
    button_success_active_bg: str
    button_danger_bg: str
    button_danger_active_bg: str
    button_delete_active_bg: str
    toggle_disabled_bg: str
    text_muted: str
    text_subtle: str
    text_disabled: str
    text_warning: str
    text_warning_alt: str
    text_success: str
    text_info: str
    status_running: str
    status_stopped: str
    badge_warning_bg: str
    panel_border: str
    separator: str
    list_row_hover: str
    table_row_alt: str
    accent: str
    primary: str
    dark: str
    light: str


def get_ui_colors() -> UIColorTokens:
    """Return the current UI color tokens pulled from the active theme palette."""

    def c(name: str, fallback: str) -> str:
        return theme_color(name, fallback)

    return UIColorTokens(
        app_bg=PROXMOX_DARK,
        card_bg=PROXMOX_MEDIUM,
        card_border=c("card_border", "#3c434e"),
        input_bg=c("input_bg", "#1f242b"),
        input_border=c("input_border", "#363c45"),
        input_border_subtle=c("input_border_subtle", "#333b47"),
        input_active_bg=c("input_active_bg", "#2f3640"),
        button_primary_bg=c("button_primary_bg", PROXMOX_ORANGE),
        button_primary_active_bg=c("button_primary_active_bg", "#ff8126"),
        button_secondary_bg=c("button_secondary_bg", "#2f3640"),
        button_secondary_active_bg=c("button_secondary_active_bg", "#3a414d"),
        button_success_bg=c("button_success_bg", "#4caf50"),
        button_success_active_bg=c("button_success_active_bg", "#45a049"),
        button_danger_bg=c("button_danger_bg", "#f44336"),
        button_danger_active_bg=c("button_danger_active_bg", "#d32f2f"),
        button_delete_active_bg=c("button_delete_active_bg", "#da190b"),
        toggle_disabled_bg=c("toggle_disabled_bg", "#555a63"),
        text_muted=c("text_muted", "#cfd3da"),
        text_subtle=c("text_subtle", "#b0b6bf"),
        text_disabled=c("text_disabled", "#666666"),
        text_warning=c("text_warning", "#ffb3a7"),
        text_warning_alt=c("text_warning_alt", "#ffb74d"),
        text_success=c("text_success", "#7ddc88"),
        text_info=c("text_info", "#33c3f0"),
        status_running=c("status_running", "#4caf50"),
        status_stopped=c("status_stopped", "#f44336"),
        badge_warning_bg=c("badge_warning_bg", "#ffb74d"),
        panel_border=c("panel_border", "#3c434e"),
        separator=c("separator", "#333b47"),
        list_row_hover=c("list_row_hover", "#2f3640"),
        table_row_alt=c("table_row_alt", "#242a32"),
        accent=PROXMOX_ACCENT,
        primary=PROXMOX_ORANGE,
        dark=PROXMOX_DARK,
        light=PROXMOX_LIGHT,
    )



