"""
APKOwl :: plugins
=================

A lightweight plugin system that lets users drop additional analysis modules
into the ``plugins/`` directory without modifying core code.

A plugin is any ``.py`` file in this package that defines a subclass of
:class:`APKOwlPlugin`. The loader discovers them, instantiates each, and the
pipeline runs them after the built-in phases, passing the same shared context.
Plugins return :class:`~core.findings.Finding` objects which are persisted and
reported exactly like built-in findings.

Why a plugin system? Real engagements often need bespoke checks — a
company-specific secret format, a proprietary obfuscator fingerprint, an
internal endpoint allow-list. Rather than forking the tool, an engineer writes a
~30 line plugin.

Contract
--------
Subclass ``APKOwlPlugin`` and implement ``analyze(context) -> list[Finding]``.
Optionally set ``name`` and ``description`` and override ``enabled()``.

The ``context`` is a duck-typed object exposing the same attributes the pipeline
builds (``package``, ``code_roots``, ``extraction``, ``manifest``, etc.), so a
plugin can reach whatever it needs. Plugins must never raise — the loader guards
them, but well-behaved plugins catch their own errors.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import pkgutil
import traceback
from typing import Any, List

from core.findings import Finding
from core.logger import log


class APKOwlPlugin:
    """Base class for all plugins."""

    name: str = "unnamed-plugin"
    description: str = ""

    def enabled(self) -> bool:
        """Return False to skip this plugin for a given run."""
        return True

    def analyze(self, context: Any) -> List[Finding]:  # pragma: no cover
        """Override: inspect the context and return findings."""
        raise NotImplementedError


def _iter_plugin_modules():
    """Yield imported modules from this package (excluding this loader)."""
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    for info in pkgutil.iter_modules([pkg_dir]):
        if info.name in ("__init__", "base"):
            continue
        try:
            module = importlib.import_module(f"plugins.{info.name}")
            yield module
        except Exception as exc:
            log.warn(f"plugin '{info.name}' failed to import: {exc}")
            log.debug(traceback.format_exc())


def discover_plugins() -> List[APKOwlPlugin]:
    """Find and instantiate every APKOwlPlugin subclass in the package."""
    found: List[APKOwlPlugin] = []
    for module in _iter_plugin_modules():
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, APKOwlPlugin)
                and attr is not APKOwlPlugin
            ):
                try:
                    instance = attr()
                    found.append(instance)
                except Exception as exc:
                    log.warn(f"plugin '{attr_name}' failed to instantiate: {exc}")
    return found


def run_plugins(context: Any) -> List[Finding]:
    """Run all enabled plugins against the context, collecting findings."""
    findings: List[Finding] = []
    plugins = discover_plugins()
    if not plugins:
        log.debug("no plugins discovered")
        return findings
    log.kv("plugins discovered", len(plugins))
    for plugin in plugins:
        try:
            if not plugin.enabled():
                log.debug(f"plugin '{plugin.name}' disabled; skipping")
                continue
            log.info(f"running plugin: {plugin.name}")
            result = plugin.analyze(context) or []
            for f in result:
                if isinstance(f, Finding):
                    findings.append(f)
            log.good(f"plugin '{plugin.name}' produced {len(result)} finding(s)")
        except Exception as exc:
            log.warn(f"plugin '{plugin.name}' raised: {exc}")
            log.debug(traceback.format_exc())
    return findings
