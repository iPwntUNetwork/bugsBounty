"""Drop-in custom tool plugin package (`tools/plugins/`).

Any Python module added to `tools/plugins/*.py` decorated with `@register_tool(...)`
is auto-loaded by `tools/registry.py` and immediately available to the crew agents.
"""
