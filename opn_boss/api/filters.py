"""Shared Jinja2 filters for OPNBoss templates."""

from __future__ import annotations

import json
import re
from typing import Any

from markupsafe import Markup, escape


def tojson_pretty(obj: Any) -> str:
    """Format a value as indented JSON string (HTML-escaped by Jinja2 autoescaping)."""
    return json.dumps(obj, indent=2, default=str)


def linkify(text: str) -> Markup:
    """Escape HTML then convert bare URLs to clickable anchor tags."""
    escaped = str(escape(text))
    linked = re.sub(
        r"(https?://[^\s<>\"']+)",
        r'<a href="\1" target="_blank" rel="noopener" '
        r'class="text-blue-600 hover:underline break-all">\1</a>',
        escaped,
    )
    return Markup(linked)


def register_filters(templates_env: object) -> None:
    """Register all custom filters on a Jinja2 Environment."""
    from jinja2 import Environment

    if isinstance(templates_env, Environment):
        templates_env.filters["linkify"] = linkify
        templates_env.filters["tojson_pretty"] = tojson_pretty
