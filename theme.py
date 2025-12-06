"""Theme loader - Dynamically loads the selected theme."""

import importlib.util
import json
from pathlib import Path

try:
    import tkinter as tk
except ImportError:
    tk = None  # tkinter not available

# Default theme name
_DEFAULT_THEME = "dark"

# Cache for loaded theme
_theme_cache = None
_theme_name_cache = None
_palette_cache: dict[str, str] = {}
THEME_PALETTE: dict[str, str] = {}


def _get_theme_preference() -> str:
    """Get theme preference from global preferences file or default."""
    default_config = Path.home() / ".config" / "Proxmox-LDC"
    pref_file = default_config / "preferences.json"
    
    if pref_file.exists():
        try:
            with pref_file.open("r", encoding="utf-8") as f:
                prefs = json.load(f)
                theme = prefs.get("theme")
                if theme in ["dark", "light"]:
                    return theme
        except Exception:
            pass
    
    return _DEFAULT_THEME


def _load_theme(theme_name: str = None) -> None:
    """Load a theme module dynamically."""
    global _theme_cache, _theme_name_cache, _palette_cache
    
    if theme_name is None:
        theme_name = _get_theme_preference()
    
    # If already loaded, don't reload
    if _theme_cache is not None and _theme_name_cache == theme_name:
        return
    
    themes_dir = Path(__file__).parent / "themes"
    theme_file = themes_dir / f"{theme_name}_theme.py"
    
    if not theme_file.exists():
        # Fallback to dark theme if requested theme doesn't exist
        theme_file = themes_dir / "dark_theme.py"
        theme_name = "dark"
    
    # Load the theme module
    spec = importlib.util.spec_from_file_location(f"{theme_name}_theme", theme_file)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load theme: {theme_name}")
    
    theme_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(theme_module)
    
    _theme_cache = theme_module
    _theme_name_cache = theme_name
    palette = getattr(theme_module, "PALETTE", {})
    if isinstance(palette, dict):
        _palette_cache = dict(palette)
    else:
        _palette_cache = {}


def get_theme_name() -> str:
    """Get the current theme name."""
    return _theme_name_cache if _theme_name_cache else _DEFAULT_THEME


def set_theme(theme_name: str) -> None:
    """Set and load a theme."""
    _load_theme(theme_name)
    reload_theme_colors()


def _ensure_theme_loaded() -> None:
    """Ensure theme is loaded (lazy loading)."""
    if _theme_cache is None:
        _load_theme()


# Initialize with theme from preference
_load_theme(_get_theme_preference())

# Export theme colors (will be updated when theme changes)
def _get_color(name: str) -> str:
    """Get a color from the current theme."""
    _ensure_theme_loaded()
    return getattr(_theme_cache, name, "#000000")


def theme_color(name: str, fallback: str | None = None) -> str:
    """Retrieve a themed color token."""
    _ensure_theme_loaded()
    return _palette_cache.get(name, fallback if fallback is not None else "#000000")


def get_palette() -> dict[str, str]:
    """Return a copy of the current theme palette."""
    _ensure_theme_loaded()
    return dict(_palette_cache)


# Export theme colors as module-level variables
# These will be updated when set_theme() is called
PROXMOX_ORANGE = _get_color("PROXMOX_ORANGE")
PROXMOX_DARK = _get_color("PROXMOX_DARK")
PROXMOX_MEDIUM = _get_color("PROXMOX_MEDIUM")
PROXMOX_LIGHT = _get_color("PROXMOX_LIGHT")
PROXMOX_ACCENT = _get_color("PROXMOX_ACCENT")
THEME_PALETTE = get_palette()


def _apply_palette_globals() -> None:
    """Expose frequently used palette tokens as module-level variables."""
    global BUTTON_PRIMARY_BG
    global BUTTON_PRIMARY_ACTIVE_BG
    global BUTTON_SECONDARY_BG
    global BUTTON_SECONDARY_ACTIVE_BG
    global BUTTON_SUCCESS_BG
    global BUTTON_SUCCESS_ACTIVE_BG
    global BUTTON_DANGER_BG
    global BUTTON_DANGER_ACTIVE_BG
    global BUTTON_DELETE_ACTIVE_BG
    global TOGGLE_DISABLED_BG
    global TEXT_MUTED
    global TEXT_SUBTLE
    global TEXT_DISABLED
    global TEXT_WARNING
    global TEXT_WARNING_ALT
    global TEXT_SUCCESS
    global TEXT_INFO
    global STATUS_RUNNING
    global STATUS_STOPPED
    global BADGE_WARNING_BG
    global PANEL_BORDER
    global SEPARATOR_COLOR
    global INPUT_BG
    global INPUT_BORDER
    global INPUT_BORDER_SUBTLE
    global INPUT_ACTIVE_BG
    global LIST_ROW_HOVER
    global TABLE_ROW_ALT

    def token(name: str, fallback: str) -> str:
        return theme_color(name, fallback)

    BUTTON_PRIMARY_BG = token("button_primary_bg", PROXMOX_ORANGE)
    BUTTON_PRIMARY_ACTIVE_BG = token("button_primary_active_bg", "#ff8126")
    BUTTON_SECONDARY_BG = token("button_secondary_bg", "#2f3640")
    BUTTON_SECONDARY_ACTIVE_BG = token("button_secondary_active_bg", "#3a414d")
    BUTTON_SUCCESS_BG = token("button_success_bg", "#4caf50")
    BUTTON_SUCCESS_ACTIVE_BG = token("button_success_active_bg", "#45a049")
    BUTTON_DANGER_BG = token("button_danger_bg", "#f44336")
    BUTTON_DANGER_ACTIVE_BG = token("button_danger_active_bg", "#d32f2f")
    BUTTON_DELETE_ACTIVE_BG = token("button_delete_active_bg", "#da190b")
    TOGGLE_DISABLED_BG = token("toggle_disabled_bg", "#555a63")
    TEXT_MUTED = token("text_muted", "#cfd3da")
    TEXT_SUBTLE = token("text_subtle", "#b0b6bf")
    TEXT_DISABLED = token("text_disabled", "#666666")
    TEXT_WARNING = token("text_warning", "#ffb3a7")
    TEXT_WARNING_ALT = token("text_warning_alt", "#ffb74d")
    TEXT_SUCCESS = token("text_success", "#7ddc88")
    TEXT_INFO = token("text_info", "#33c3f0")
    STATUS_RUNNING = token("status_running", "#4caf50")
    STATUS_STOPPED = token("status_stopped", "#f44336")
    BADGE_WARNING_BG = token("badge_warning_bg", "#ffb74d")
    PANEL_BORDER = token("panel_border", "#3c434e")
    SEPARATOR_COLOR = token("separator", "#333b47")
    INPUT_BG = token("input_bg", "#1f242b")
    INPUT_BORDER = token("input_border", "#363c45")
    INPUT_BORDER_SUBTLE = token("input_border_subtle", "#333b47")
    INPUT_ACTIVE_BG = token("input_active_bg", "#2f3640")
    LIST_ROW_HOVER = token("list_row_hover", "#2f3640")
    TABLE_ROW_ALT = token("table_row_alt", "#242a32")


def reload_theme_colors() -> None:
    """Reload theme colors (call after changing theme)."""
    global PROXMOX_ORANGE, PROXMOX_DARK, PROXMOX_MEDIUM, PROXMOX_LIGHT, PROXMOX_ACCENT, THEME_PALETTE
    PROXMOX_ORANGE = _get_color("PROXMOX_ORANGE")
    PROXMOX_DARK = _get_color("PROXMOX_DARK")
    PROXMOX_MEDIUM = _get_color("PROXMOX_MEDIUM")
    PROXMOX_LIGHT = _get_color("PROXMOX_LIGHT")
    PROXMOX_ACCENT = _get_color("PROXMOX_ACCENT")
    THEME_PALETTE = get_palette()
    _apply_palette_globals()

# Initialize palette globals on module load
_apply_palette_globals()


def update_all_ttk_styles(root_widget=None) -> None:
    """Update all ttk styles that use theme colors."""
    if tk is None:
        return
    
    try:
        from tkinter import ttk
        style = ttk.Style()
        
        # Update common ttk styles
        style.configure(
            "TCombobox",
            fieldbackground=PROXMOX_DARK,
            background=PROXMOX_DARK,
            foreground=PROXMOX_LIGHT,
            borderwidth=0,
            relief="flat",
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", PROXMOX_DARK)],
            background=[("readonly", PROXMOX_DARK)],
            foreground=[("readonly", PROXMOX_LIGHT)],
        )
        
        # Update Proxmox.TCombobox if it exists
        try:
            style.configure(
                "Proxmox.TCombobox",
                fieldbackground=PROXMOX_DARK,
                background=PROXMOX_DARK,
                foreground=PROXMOX_LIGHT,
                bordercolor=theme_color("input_border", "#363c45"),
                arrowcolor=PROXMOX_LIGHT,
            )
            style.map(
                "Proxmox.TCombobox",
                fieldbackground=[("readonly", PROXMOX_DARK)],
                foreground=[("readonly", PROXMOX_LIGHT)],
            )
        except Exception:
            pass
        
        # Update wizard styles if they exist
        wizard_styles = [
            "Wizard.TFrame", "Wizard.Card.TFrame", "Wizard.TLabel",
            "WizardHeader.TLabel", "Wizard.SubHeader.TLabel",
            "Wizard.TButton", "Wizard.Secondary.TButton",
            "Wizard.TEntry", "Wizard.TCombobox"
        ]
        
        for style_name in wizard_styles:
            try:
                # Get current config to see what needs updating
                current_config = style.configure(style_name)
                if current_config:
                    # Update background if it exists
                    if "background" in current_config:
                        if current_config["background"] in ["#1b1f24", "#ffffff"]:
                            style.configure(style_name, background=PROXMOX_DARK)
                        elif current_config["background"] in ["#2a3038", "#e8f4f8"]:
                            style.configure(style_name, background=PROXMOX_MEDIUM)
                    # Update foreground if it exists
                    if "foreground" in current_config:
                        if current_config["foreground"] in ["#f4f4f4", "#1a1a1a"]:
                            style.configure(style_name, foreground=PROXMOX_LIGHT)
                    # Update fieldbackground for entries/comboboxes
                    if "fieldbackground" in current_config:
                        style.configure(style_name, fieldbackground=PROXMOX_DARK)
            except Exception:
                pass
                
    except Exception:
        pass


def save_theme_preference(theme_name: str) -> None:
    """Save theme preference to global preferences file."""
    default_config = Path.home() / ".config" / "Proxmox-LDC"
    default_config.mkdir(parents=True, exist_ok=True)
    pref_file = default_config / "preferences.json"
    
    try:
        prefs = {}
        if pref_file.exists():
            with pref_file.open("r", encoding="utf-8") as f:
                prefs = json.load(f)
        prefs["theme"] = theme_name
        with pref_file.open("w", encoding="utf-8") as f:
            json.dump(prefs, f, indent=2)
    except Exception:
        pass


# All possible theme colors (both dark and light themes)
_ALL_THEME_COLORS = {
    # Dark theme colors
    "#1b1f24", "#1f242b", "#2a3038", "#2f3640", "#242a32", "#353c45", "#3a414d",
    "#f4f4f4", "#ff6c00", "#ff8126", "#33c3f0",
    # Light theme colors  
    "#ffffff", "#e8f4f8", "#1a1a1a", "#0066cc",
    # Common text/status colors
    "#cfd3da", "#b0b6bf", "#4caf50", "#f44336", "#45a049", "#d32f2f",
    "#7ddc88", "#ffb3a7", "#ffb74d", "#555a63", "#666666",
    # Border/separator colors
    "#363c45", "#3c434e", "#333b47",
}

def _is_theme_color(color: str) -> bool:
    """Check if a color matches any theme color (dark or light)."""
    if not color:
        return False
    color_lower = color.lower()
    # Check against known theme colors
    if color_lower in _ALL_THEME_COLORS:
        return True
    # Also check if it matches current theme variables (might be stale)
    if color_lower in [PROXMOX_DARK.lower(), PROXMOX_MEDIUM.lower(), 
                       PROXMOX_LIGHT.lower(), PROXMOX_ORANGE.lower(), PROXMOX_ACCENT.lower()]:
        return True
    return False


def apply_theme_to_widget(widget, visited: set | None = None) -> None:
    """Recursively apply theme colors to a widget and all its children."""
    if tk is None:
        return  # tkinter not available
    
    if visited is None:
        visited = set()
    
    widget_id = id(widget)
    if widget_id in visited:
        return
    visited.add(widget_id)
    
    try:
        if not widget.winfo_exists():
            return
        
        widget_type = widget.winfo_class()
        
        # Get current colors
        try:
            current_bg = widget.cget("bg") if hasattr(widget, "cget") else None
            current_fg = widget.cget("fg") if hasattr(widget, "cget") else None
        except Exception:
            current_bg = None
            current_fg = None
        
        # Update widget based on type
        if isinstance(widget, (tk.Frame, tk.Toplevel)):
            if current_bg and _is_theme_color(current_bg):
                # Determine if it should be dark or medium based on common patterns
                if current_bg in ["#1b1f24", "#1f242b", "#242a32", "#ffffff"]:
                    widget.configure(bg=PROXMOX_DARK)
                elif current_bg in ["#2a3038", "#2f3640", "#353c45", "#3a414d", "#e8f4f8"]:
                    widget.configure(bg=PROXMOX_MEDIUM)
                # Also update if it matches current theme colors (might be stale)
                elif current_bg == PROXMOX_DARK or current_bg == PROXMOX_MEDIUM:
                    # Force update to ensure it's using the latest theme value
                    widget.configure(bg=PROXMOX_DARK if current_bg == PROXMOX_DARK else PROXMOX_MEDIUM)
        
        elif isinstance(widget, tk.Label):
            if current_bg and _is_theme_color(current_bg):
                if current_bg in ["#1b1f24", "#1f242b", "#242a32", "#ffffff"]:
                    widget.configure(bg=PROXMOX_DARK)
                elif current_bg in ["#2a3038", "#2f3640", "#353c45", "#3a414d", "#e8f4f8"]:
                    widget.configure(bg=PROXMOX_MEDIUM)
                elif current_bg == PROXMOX_DARK or current_bg == PROXMOX_MEDIUM:
                    widget.configure(bg=PROXMOX_DARK if current_bg == PROXMOX_DARK else PROXMOX_MEDIUM)
            
            if current_fg and _is_theme_color(current_fg):
                if current_fg in ["#f4f4f4", "#ffffff", "#1a1a1a"]:
                    widget.configure(fg=PROXMOX_LIGHT)
                elif current_fg in ["#cfd3da", "#b0b6bf"]:
                    widget.configure(fg=theme_color("text_muted", "#cfd3da"))
                elif current_fg in ["#ff6c00", "#ff8126", "#0066cc"]:
                    widget.configure(fg=PROXMOX_ORANGE)
                elif current_fg == PROXMOX_LIGHT or current_fg == PROXMOX_ORANGE:
                    widget.configure(fg=PROXMOX_LIGHT if current_fg == PROXMOX_LIGHT else PROXMOX_ORANGE)
        
        elif isinstance(widget, tk.Button):
            if current_bg and _is_theme_color(current_bg):
                if current_bg in ["#ff6c00", "#ff8126", "#0066cc"]:
                    widget.configure(bg=PROXMOX_ORANGE)
                elif current_bg in ["#2f3640", "#3a414d", "#353c45"]:
                    widget.configure(bg=theme_color("button_secondary_bg", "#2f3640"))
                elif current_bg in ["#4caf50", "#45a049"]:
                    widget.configure(bg=theme_color("button_success_bg", "#4caf50"))
                elif current_bg in ["#f44336", "#d32f2f"]:
                    widget.configure(bg=theme_color("button_danger_bg", "#f44336"))
                elif current_bg == PROXMOX_ORANGE:
                    widget.configure(bg=PROXMOX_ORANGE)
            
            # Update activebackground
            try:
                current_active = widget.cget("activebackground")
                if current_active and _is_theme_color(current_active):
                    if current_active in ["#ff8126"]:
                        widget.configure(activebackground=theme_color("button_primary_active_bg", "#ff8126"))
                    elif current_active in ["#3a414d", "#353c45"]:
                        widget.configure(activebackground=theme_color("button_secondary_active_bg", "#3a414d"))
            except Exception:
                pass
        
        elif isinstance(widget, tk.Entry):
            if current_bg and _is_theme_color(current_bg):
                if current_bg in ["#1b1f24", "#1f242b", "#2a3038", "#ffffff"]:
                    widget.configure(bg=PROXMOX_DARK)
                elif current_bg == PROXMOX_DARK:
                    widget.configure(bg=PROXMOX_DARK)
            
            if current_fg and _is_theme_color(current_fg):
                widget.configure(fg=PROXMOX_LIGHT)
            
            # Update highlight colors
            try:
                current_highlight = widget.cget("highlightbackground")
                if current_highlight:
                    widget.configure(highlightbackground=theme_color("input_border", "#363c45"))
            except Exception:
                pass
        
        elif isinstance(widget, tk.Canvas):
            if current_bg and _is_theme_color(current_bg):
                if current_bg in ["#1b1f24", "#1f242b", "#2a3038", "#2f3640", "#ffffff"]:
                    widget.configure(bg=PROXMOX_DARK)
                elif current_bg in ["#2a3038", "#2f3640", "#353c45", "#e8f4f8"]:
                    widget.configure(bg=PROXMOX_MEDIUM)
                elif current_bg == PROXMOX_DARK or current_bg == PROXMOX_MEDIUM:
                    widget.configure(bg=PROXMOX_DARK if current_bg == PROXMOX_DARK else PROXMOX_MEDIUM)
        
        # Handle OptionMenu (special case - has a menu attribute)
        if hasattr(widget, "menu") and isinstance(widget, tk.OptionMenu):
            try:
                menu = widget["menu"]
                menu.configure(bg=theme_color("button_secondary_bg", "#2f3640"), fg=PROXMOX_LIGHT)
            except Exception:
                pass
        
        # Recursively update children
        try:
            for child in widget.winfo_children():
                apply_theme_to_widget(child, visited)
        except Exception:
            pass
            
    except Exception:
        # If widget is destroyed or inaccessible, skip it
        pass
