# Copyright 2023 The Bazel Authors. All rights reserved.
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

"""Utility class to inspect an extracted wheel directory"""

import email
import platform
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import installer
from packaging.requirements import Requirement
from pip._vendor.packaging.utils import canonicalize_name


class OS(Enum):
    linux = 1
    osx = 2
    windows = 3
    darwin = osx
    win32 = windows


class Arch(Enum):
    x86_64 = 1
    x86_32 = 2
    aarch64 = 3
    ppc = 4
    s390x = 5
    amd64 = x86_64
    arm64 = aarch64
    i386 = x86_32
    i686 = x86_32
    x86 = x86_32
    ppc64le = ppc


@dataclass(frozen=True)
class Platform:
    os: OS
    arch: Optional[Arch] = None

    @classmethod
    def all(cls, want_os: Optional[OS] = None) -> List["Platform"]:
        return sorted(
            [
                cls(os=os, arch=arch)
                for os in OS
                for arch in Arch
                if not want_os or want_os == os
            ]
        )

    @classmethod
    def host(cls) -> List["Platform"]:
        """Use the Python interpreter to detect the platform.

        We extract `os` from sys.platform and `arch` from platform.machine

        Returns:
            A list of parsed values which makes the signature the same as
            `Platform.all` and `Platform.from_string`.
        """
        return [
            cls(
                os=OS[sys.platform.lower()],
                # FIXME @aignas 2023-12-13: Hermetic toolchain on Windows 3.11.6
                # is returning an empty string here, so lets default to x86_64
                arch=Arch[platform.machine().lower() or "x86_64"],
            )
        ]

    def __lt__(self, other: Any) -> bool:
        """Add a comparison method, so that `sorted` returns the most specialized platforms first."""
        if not isinstance(other, Platform) or other is None:
            raise ValueError(f"cannot compare {other} with Platform")

        if self.arch is None and other.arch is not None:
            return True

        if self.arch is not None and other.arch is None:
            return True

        # Here we ensure that we sort by OS before sorting by arch

        if self.arch is None and other.arch is None:
            return self.os.value < other.os.value

        if self.os.value < other.os.value:
            return True

        if self.os.value == other.os.value:
            return self.arch.value < other.arch.value

        return False

    def __str__(self) -> str:
        if self.arch is None:
            return f"@platforms//os:{self.os.name.lower()}"

        return self.os.name.lower() + "_" + self.arch.name.lower()

    @classmethod
    def from_string(cls, platform: Union[str, List[str]]) -> List["Platform"]:
        """Parse a string and return a list of platforms"""
        platform = [platform] if isinstance(platform, str) else list(platform)
        ret = set()
        for p in platform:
            if p == "host":
                ret.update(cls.host())
            elif p == "all":
                ret.update(cls.all())
            elif p.endswith("*"):
                os, _, _ = p.partition("_")
                ret.update(cls.all(OS[os]))
            else:
                os, _, arch = p.partition("_")
                ret.add(cls(os=OS[os], arch=Arch[arch]))

        return sorted(ret)

    # NOTE @aignas 2023-12-05: below is the minimum number of accessors that are defined in
    # https://peps.python.org/pep-0496/ to make rules_python generate dependencies.
    #
    # WARNING: It may not work in cases where the python implementation is different between
    # different platforms.

    # derived from OS
    @property
    def os_name(self) -> str:
        if self.os == OS.linux or self.os == OS.osx:
            return "posix"
        elif self.os == OS.windows:
            return "nt"
        else:
            return ""

    @property
    def sys_platform(self) -> str:
        if self.os == OS.linux:
            return "linux"
        elif self.os == OS.osx:
            return "darwin"
        elif self.os == OS.windows:
            return "win32"
        else:
            return ""

    @property
    def platform_system(self) -> str:
        if self.os == OS.linux:
            return "Linux"
        elif self.os == OS.osx:
            return "Darwin"
        elif self.os == OS.windows:
            return "Windows"

    # derived from OS and Arch
    @property
    def platform_machine(self) -> str:
        """Guess the target 'platform_machine' marker.

        NOTE @aignas 2023-12-05: this may not work on really new systems, like
        Windows if they define the platform markers in a different way.
        """
        if self.arch == Arch.x86_64:
            return "x86_64"
        elif self.arch == Arch.x86_32 and self.os != OS.osx:
            return "i386"
        elif self.arch == Arch.x86_32:
            return ""
        elif self.arch == Arch.aarch64 and self.os == OS.linux:
            return "aarch64"
        elif self.arch == Arch.aarch64:
            # Assuming that OSX and Windows use this one since the precedent is set here:
            # https://github.com/cgohlke/win_arm64-wheels
            return "arm64"
        elif self.os != OS.linux:
            return ""
        elif self.arch == Arch.ppc64le:
            return "ppc64le"
        elif self.arch == Arch.s390x:
            return "s390x"
        else:
            return ""

    def env_markers(self, extra: str) -> Dict[str, str]:
        return {
            "extra": extra,
            "os_name": self.os_name,
            "sys_platform": self.sys_platform,
            "platform_machine": self.platform_machine,
            "platform_system": self.platform_system,
            "platform_release": "",  # unset
            "platform_version": "",  # unset
            # we assume that the following are the same as the interpreter used to setup the deps:
            # "implementation_version": "X.Y.Z",
            # "implementation_name": "cpython"
            # "python_version": "X.Y",
            # "python_full_version": "X.Y.Z",
            # "platform_python_implementation: "CPython",
        }


@dataclass(frozen=True)
class FrozenDeps:
    deps: List[str]
    deps_select: Dict[str, List[str]]


class Deps:
    def __init__(
        self,
        name: str,
        extras: Optional[Set[str]] = None,
        platforms: Optional[Set[Platform]] = None,
    ):
        self.name: str = Deps._normalize(name)
        self._deps: Set[str] = set()
        self._select: Dict[Platform, Set[str]] = defaultdict(set)
        self._want_extras: Set[str] = extras or {""}  # empty strings means no extras
        self._platforms: Set[Platform] = platforms or set()

    def _add(self, dep: str, platform: Optional[Platform]):
        dep = Deps._normalize(dep)

        # Packages may create dependency cycles when specifying optional-dependencies / 'extras'.
        # Example: github.com/google/etils/blob/a0b71032095db14acf6b33516bca6d885fe09e35/pyproject.toml#L32.
        if dep == self.name:
            return

        if platform:
            self._select[platform].add(dep)
        else:
            self._deps.add(dep)

    @staticmethod
    def _normalize(name: str) -> str:
        return re.sub(r"[-_.]+", "_", name).lower()

    def add(self, *wheel_reqs: str) -> None:
        reqs = [Requirement(wheel_req) for wheel_req in wheel_reqs]

        # Resolve any extra extras due to self-edges
        self._want_extras = self._resolve_extras(reqs)

        # process self-edges first to resolve the extras used
        for req in reqs:
            self._add_req(req)

    def _resolve_extras(self, reqs: List[Requirement]) -> Set[str]:
        """Resolve extras which are due to depending on self[some_other_extra].

        Some packages may have cyclic dependencies resulting from extras being used, one example is
        `elint`, where we have one set of extras as aliases for other extras
        and we have an extra called 'all' that includes all other extras.

        When the `requirements.txt` is generated by `pip-tools`, then it is likely that
        this step is not needed, but for other `requirements.txt` files this may be useful.

        NOTE @aignas 2023-12-08: the extra resolution is not platform dependent, but
        in order for it to become platform dependent we would have to have separate targets for each extra in
        self._want_extras.
        """
        extras = self._want_extras

        self_reqs = []
        for req in reqs:
            if Deps._normalize(req.name) != self.name:
                continue

            if req.marker is None:
                # I am pretty sure we cannot reach this code as it does not
                # make sense to specify packages in this way, but since it is
                # easy to handle, lets do it.
                #
                # TODO @aignas 2023-12-08: add a test
                extras = extras | req.extras
            else:
                # process these in a separate loop
                self_reqs.append(req)

        # A double loop is not strictly optimal, but always correct without recursion
        for req in self_reqs:
            if any(req.marker.evaluate({"extra": extra}) for extra in extras):
                extras = extras | req.extras
            else:
                continue

            # Iterate through all packages to ensure that we include all of the extras from previously
            # visited packages.
            for req_ in self_reqs:
                if any(req_.marker.evaluate({"extra": extra}) for extra in extras):
                    extras = extras | req_.extras

        return extras

    def _add_req(self, req: Requirement) -> None:
        extras = self._want_extras

        if req.marker is None:
            self._add(req.name, None)
            return

        marker_str = str(req.marker)

        # NOTE @aignas 2023-12-08: in order to have reasonable select statements
        # we do have to have some parsing of the markers, so it begs the question
        # if packaging should be reimplemented in Starlark to have the best solution
        # for now we will implement it in Python and see what the best parsing result
        # can be before making this decision.
        if not self._platforms or not any(
            tag in marker_str
            for tag in [
                "os_name",
                "sys_platform",
                "platform_machine",
                "platform_system",
            ]
        ):
            if any(req.marker.evaluate({"extra": extra}) for extra in extras):
                self._add(req.name, None)
            return

        for plat in self._platforms:
            if not any(
                req.marker.evaluate(plat.env_markers(extra)) for extra in extras
            ):
                continue

            if "platform_machine" in marker_str:
                self._add(req.name, plat)
            else:
                self._add(req.name, Platform(plat.os))

    def build(self) -> FrozenDeps:
        if not self._select:
            return FrozenDeps(
                deps=sorted(self._deps),
                deps_select={},
            )

        # Get all of the OS-specific dependencies applicable to all architectures
        select = {
            p: deps for p, deps in self._select.items() if deps and p.arch is None
        }
        # Now add them to all arch specific dependencies
        select.update(
            {
                p: deps | select.get(Platform(p.os), set())
                for p, deps in self._select.items()
                if deps and p.arch is not None
            }
        )

        return FrozenDeps(
            deps=sorted(self._deps),
            deps_select={str(p): sorted(deps) for p, deps in sorted(select.items())},
        )


class Wheel:
    """Representation of the compressed .whl file"""

    def __init__(self, path: Path):
        self._path = path

    @property
    def path(self) -> str:
        return self._path

    @property
    def name(self) -> str:
        # TODO Also available as installer.sources.WheelSource.distribution
        name = str(self.metadata["Name"])
        return canonicalize_name(name)

    @property
    def metadata(self) -> email.message.Message:
        with installer.sources.WheelFile.open(self.path) as wheel_source:
            metadata_contents = wheel_source.read_dist_info("METADATA")
            metadata = installer.utils.parse_metadata_file(metadata_contents)
        return metadata

    @property
    def version(self) -> str:
        # TODO Also available as installer.sources.WheelSource.version
        return str(self.metadata["Version"])

    def entry_points(self) -> Dict[str, Tuple[str, str]]:
        """Returns the entrypoints defined in the current wheel

        See https://packaging.python.org/specifications/entry-points/ for more info

        Returns:
            Dict[str, Tuple[str, str]]: A mapping of the entry point's name to it's module and attribute
        """
        with installer.sources.WheelFile.open(self.path) as wheel_source:
            if "entry_points.txt" not in wheel_source.dist_info_filenames:
                return dict()

            entry_points_mapping = dict()
            entry_points_contents = wheel_source.read_dist_info("entry_points.txt")
            entry_points = installer.utils.parse_entrypoints(entry_points_contents)
            for script, module, attribute, script_section in entry_points:
                if script_section == "console":
                    entry_points_mapping[script] = (module, attribute)

            return entry_points_mapping

    def dependencies(
        self,
        extras_requested: Set[str] = None,
        platforms: Optional[Set[Platform]] = None,
    ) -> FrozenDeps:
        dependency_set = Deps(
            self.name,
            extras=extras_requested,
            platforms=platforms,
        )
        for wheel_req in self.metadata.get_all("Requires-Dist", []):
            dependency_set.add(wheel_req)

        return dependency_set.build()

    def unzip(self, directory: str) -> None:
        installation_schemes = {
            "purelib": "/site-packages",
            "platlib": "/site-packages",
            "headers": "/include",
            "scripts": "/bin",
            "data": "/data",
        }
        destination = installer.destinations.SchemeDictionaryDestination(
            installation_schemes,
            # TODO Should entry_point scripts also be handled by installer rather than custom code?
            interpreter="/dev/null",
            script_kind="posix",
            destdir=directory,
            bytecode_optimization_levels=[],
        )

        with installer.sources.WheelFile.open(self.path) as wheel_source:
            installer.install(
                source=wheel_source,
                destination=destination,
                additional_metadata={
                    "INSTALLER": b"https://github.com/bazelbuild/rules_python",
                },
            )
