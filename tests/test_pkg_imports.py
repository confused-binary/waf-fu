"""PKG-01: every module in the restructured package must import without error."""

import importlib

MODULES = [
    "waf_fu.cli",
    "waf_fu.models",
    "waf_fu.cloudwatch",
    "waf_fu.jwt",
    "waf_fu.debug",
    "waf_fu.replay.chrome",
    "waf_fu.replay.firefox",
    "waf_fu.replay.curl",
    "waf_fu.tui",
    "waf_fu.export",
    "waf_fu.replay",
]


def test_all_modules_import_without_error():
    for module_name in MODULES:
        importlib.import_module(module_name)
