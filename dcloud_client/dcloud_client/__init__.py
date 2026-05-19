"""Compatibility package for running module commands from this directory.

When the current working directory is ``dcloud_client/``, Python cannot normally
resolve ``python -m dcloud_client.main`` because the import root is already the
package directory. Extending this package path to the parent directory lets the
standard package modules be found without changing application imports.
"""

from __future__ import annotations

from pathlib import Path
from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)
_parent_package_dir = Path(__file__).resolve().parents[1]
_parent_package_dir_str = str(_parent_package_dir)
if _parent_package_dir_str not in __path__:
    __path__.append(_parent_package_dir_str)

__version__ = "0.1.0"
