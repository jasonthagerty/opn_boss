"""Shared Jinja2 filters for OPNBoss templates."""

from __future__ import annotations

import re

from markupsafe import Markup, escape


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
