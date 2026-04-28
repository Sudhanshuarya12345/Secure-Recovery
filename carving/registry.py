"""
pyrecovery.carving.registry — Central registry for file format signatures.

Performance design:
- Primary lookup: dict[int, list[BaseSignature]] keyed by the first byte
  of each header. During scanning, we check data[position] and get O(1)
  lookup of candidate signatures instead of iterating all 30+.
- Offset signatures: formats with header_offset > 0 (e.g., MP4) are stored
  separately and checked at reduced frequency.
- Auto-discovery: scans carving/signatures/ and plugins/ at startup.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Optional

from carving.base_signature import BaseSignature
from utils.logger import get_logger

logger = get_logger(__name__)


class SignatureRegistry:
    """Central registry for all file format signatures.

    Usage::

        registry = SignatureRegistry()
        registry.register_builtins()   # Load all built-in signatures
        registry.discover_plugins()     # Load plugins from plugins/ folder

        # During scanning:
        candidates = registry.get_by_first_byte(data[pos])
        for sig in candidates:
            if sig.match_header(data, pos):
                # Found a match!
    """

    def __init__(self) -> None:
        self._by_first_byte: dict[int, list[BaseSignature]] = {}
        self._offset_sigs: list[BaseSignature] = []
        self._all: list[BaseSignature] = []

    def register(self, sig: BaseSignature) -> None:
        """Register a single signature.

        Args:
            sig: A BaseSignature instance to register.

        The signature is indexed by the first byte of each of its headers
        for O(1) lookup during scanning.
        """
        self._all.append(sig)

        if sig.header_offset > 0:
            # Signatures with non-zero header_offset need special handling
            self._offset_sigs.append(sig)
            logger.debug(
                "Registered offset signature: %s (offset=%d)",
                sig.name, sig.header_offset,
            )
        else:
            for header in sig.headers:
                if len(header) == 0:
                    continue
                first_byte = header[0]
                if first_byte not in self._by_first_byte:
                    self._by_first_byte[first_byte] = []
                # Avoid duplicate registration
                if sig not in self._by_first_byte[first_byte]:
                    self._by_first_byte[first_byte].append(sig)

        logger.debug("Registered: %s (.%s) [%s]", sig.name, sig.extension, sig.category)

    def register_builtins(self) -> None:
        """Import and register all built-in signatures from carving/signatures/.

        Walks the carving.signatures package tree, imports every module,
        and finds all concrete BaseSignature subclasses.
        """
        import carving.signatures as sig_package

        registered_count = 0
        for importer, modname, ispkg in pkgutil.walk_packages(
            sig_package.__path__, prefix="carving.signatures."
        ):
            if ispkg:
                continue
            try:
                module = importlib.import_module(modname)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseSignature)
                        and attr is not BaseSignature
                        and attr.name  # Skip abstract classes without name
                    ):
                        instance = attr()
                        self.register(instance)
                        registered_count += 1
            except Exception as e:
                logger.warning("Failed to load signature module %s: %s", modname, e)

        logger.info("Registered %d built-in signatures", registered_count)

    def discover_plugins(self, plugin_dir: str = "plugins") -> None:
        """Auto-discover and register plugin signatures from a directory.

        Scans the plugin directory for .py files, imports them, and registers
        any BaseSignature subclasses found.

        Args:
            plugin_dir: Path to the plugins directory.
        """
        plugin_path = Path(plugin_dir)
        if not plugin_path.exists():
            logger.debug("Plugin directory not found: %s", plugin_dir)
            return

        registered_count = 0
        for py_file in plugin_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            module_name = f"plugins.{py_file.stem}"
            try:
                module = importlib.import_module(module_name)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseSignature)
                        and attr is not BaseSignature
                        and attr.name
                    ):
                        instance = attr()
                        self.register(instance)
                        registered_count += 1
            except Exception as e:
                logger.warning("Failed to load plugin %s: %s", py_file.name, e)

        if registered_count > 0:
            logger.info("Registered %d plugin signatures from %s", registered_count, plugin_dir)

    def get_by_first_byte(self, byte: int) -> list[BaseSignature]:
        """O(1) lookup: return all signatures whose header starts with this byte.

        Args:
            byte: The first byte value (0-255) at the current scan position.

        Returns:
            List of candidate signatures to check, or empty list.
        """
        return self._by_first_byte.get(byte, [])

    def get_offset_signatures(self) -> list[BaseSignature]:
        """Return signatures with header_offset > 0.

        These need special handling during scanning because their magic bytes
        don't appear at the file's first byte.

        Returns:
            List of offset-based signatures (e.g., MP4 with ftyp at +4).
        """
        return self._offset_sigs

    def get_all(self) -> list[BaseSignature]:
        """Return all registered signatures.

        Returns:
            List of all BaseSignature instances.
        """
        return list(self._all)

    @property
    def count(self) -> int:
        """Total number of registered signatures."""
        return len(self._all)

    def summary(self) -> str:
        """Human-readable summary of registered signatures.

        Returns:
            Formatted string listing all signatures grouped by category.
        """
        by_category: dict[str, list[str]] = {}
        for sig in self._all:
            cat = sig.category or "unknown"
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(f".{sig.extension} ({sig.name})")

        lines = [f"Registered signatures: {self.count}"]
        for cat in sorted(by_category.keys()):
            lines.append(f"  {cat}: {', '.join(sorted(by_category[cat]))}")
        return "\n".join(lines)

    def __len__(self) -> int:
        return self.count

    def __repr__(self) -> str:
        return f"SignatureRegistry(count={self.count})"
