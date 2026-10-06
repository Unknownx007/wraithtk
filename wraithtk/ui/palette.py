"""WraithTK palette — black / white / ghost-green."""

PALETTE = {
    "primary":   "#00ff41",   # matrix green
    "secondary": "#e8e8e8",   # bone white
    "accent":    "#4d9fff",   # signal blue
    "danger":    "#ff0844",   # hot red
    "warning":   "#ffb000",   # amber
    "success":   "#39ff14",   # neon green
    "text":      "#d0d0d0",   # dim white
    "dim":       "#4a4a4a",   # mid gray
    "mute":      "#1a1a1a",   # near black
    "border":    "#2a2a2a",
    "bg":        "#000000",
    "panel_bg":  "#0a0a0a",
}

SEV_COLORS = {
    "critical": "#ff0844",
    "high":     "#ff3366",
    "medium":   "#ffb000",
    "low":      "#4d9fff",
    "info":     "#4a4a4a",
}


def sev_color(sev: str) -> str:
    return SEV_COLORS.get(sev.lower(), PALETTE["dim"])
