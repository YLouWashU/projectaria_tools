# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import subprocess
import sys

import pkg_resources

## These modules get installed on importing the cli_lib module
def _install_deps():
    """These are all the necessary modules to be installed before running the CLI"""
    _required_modules = {
        "aiofiles",
        "aiohttp",
        "projectaria-tools",
        "pycryptodome",
        "rich",
        "transitions",
        "xxhash",
    }
    installed = {pkg.key for pkg in pkg_resources.working_set}
    _modules_to_install = _required_modules - installed
    if _modules_to_install:
        print(
            f"The following modules need to be installed before running the CLI:\n{_modules_to_install}"
        )
        subprocess.run(
            [sys.executable, "-m", "pip", "install"] + list(_modules_to_install)
        )


_install_deps()

from .run import run  # noqa
