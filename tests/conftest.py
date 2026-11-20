

import os as _os

import pytest as _pytest


@_pytest.fixture(autouse=True)
def _no_real_cmake_configure(request, monkeypatch):
    """Inference tests build throw-away trees with CMakeLists.txt; never run a real cmake on them.
    test_build_probe.py exercises the probe itself with a fake cmake."""
    if request.module.__name__.split(".")[-1] != "test_build_probe":
        monkeypatch.setenv("ACCUKNOX_BUILD_PROBE", "off")
