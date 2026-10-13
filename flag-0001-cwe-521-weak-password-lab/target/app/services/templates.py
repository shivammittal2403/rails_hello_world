"""Jinja2 template environment singleton."""
from __future__ import annotations

import os

from fastapi.templating import Jinja2Templates

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../target/app
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


def add_template_context(processor):
    """Register a context processor (callable(request)->dict) for all templates."""
    from jinja2 import pass_context

    original = templates.TemplateResponse

    def patched(request, name, context=None, *args, **kwargs):
        ctx = dict(context or {})
        ctx.update(processor(request))
        return original(request, name, ctx, *args, **kwargs)

    templates.TemplateResponse = patched
    return processor
