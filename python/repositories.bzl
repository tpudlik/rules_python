# Copyright 2022 The Bazel Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""This file contains macros to be called during WORKSPACE evaluation.

For historic reasons, pip_repositories() is defined in //python:pip.bzl.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", _http_archive = "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
load("//python/pip_install:repositories.bzl", "pip_install_dependencies")
load("//python/private:auth.bzl", "get_auth")
load("//python/private:bzlmod_enabled.bzl", "BZLMOD_ENABLED")
load("//python/private:coverage_deps.bzl", "coverage_dep")
load("//python/private:full_version.bzl", "full_version")
load("//python/private:internal_config_repo.bzl", "internal_config_repo")
load(
    "//python/private:toolchains_repo.bzl",
    "multi_toolchain_aliases",
    "toolchain_aliases",
    "toolchains_repo",
)
load("//python/private:which.bzl", "which_with_fail")
load(
    ":versions.bzl",
    "DEFAULT_RELEASE_BASE_URL",
    "PLATFORMS",
    "TOOL_VERSIONS",
    "get_release_info",
)

def http_archive(**kwargs):
    maybe(_http_archive, **kwargs)

def py_repositories():
    """Runtime dependencies that users must install.

    This function should be loaded and called in the user's WORKSPACE.
    With bzlmod enabled, this function is not needed since MODULE.bazel handles transitive deps.
    """
    maybe(
        internal_config_repo,
        name = "rules_python_internal",
    )
    http_archive(
        name = "bazel_skylib",
        sha256 = "74d544d96f4a5bb630d465ca8bbcfe231e3594e5aae57e1edbf17a6eb3ca2506",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.3.0/bazel-skylib-1.3.0.tar.gz",
            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.3.0/bazel-skylib-1.3.0.tar.gz",
        ],
    )
    pip_install_dependencies()

########
# Remaining content of the file is only used to support toolchains.
########

STANDALONE_INTERPRETER_FILENAME = "STANDALONE_INTERPRETER"

def is_standalone_interpreter(rctx, python_interpreter_path):
    """Query a python interpreter target for whether or not it's a rules_rust provided toolchain

    Args:
        rctx (repository_ctx): The repository rule's context object.
        python_interpreter_path (path): A path representing the interpreter.

    Returns:
        bool: Whether or not the target is from a rules_python generated toolchain.
    """

    # Only update the location when using a hermetic toolchain.
    if not python_interpreter_path:
        return False

    # This is a rules_python provided toolchain.
    return rctx.execute([
        "ls",
        "{}/{}".format(
            python_interpreter_path.dirname,
            STANDALONE_INTERPRETER_FILENAME,
        ),
    ]).return_code == 0

def _python_repository_impl(rctx):
    if rctx.attr.distutils and rctx.attr.distutils_content:
        fail("Only one of (distutils, distutils_content) should be set.")
    if bool(rctx.attr.url) == bool(rctx.attr.urls):
        fail("Exactly one of (url, urls) must be set.")

    platform = rctx.attr.platform
    python_version = rctx.attr.python_version
    python_short_version = python_version.rpartition(".")[0]
    release_filename = rctx.attr.release_filename
    urls = rctx.attr.urls or [rctx.attr.url]
    auth = get_auth(rctx, urls)

    if release_filename.endswith(".zst"):
        rctx.download(
            url = urls,
            sha256 = rctx.attr.sha256,
            output = release_filename,
            auth = auth,
        )
        unzstd = rctx.which("unzstd")
        if not unzstd:
            url = rctx.attr.zstd_url.format(version = rctx.attr.zstd_version)
            rctx.download_and_extract(
                url = url,
                sha256 = rctx.attr.zstd_sha256,
                auth = auth,
            )
            working_directory = "zstd-{version}".format(version = rctx.attr.zstd_version)

            make_result = rctx.execute(
                [which_with_fail("make", rctx), "--jobs=4"],
                timeout = 600,
                quiet = True,
                working_directory = working_directory,
            )
            if make_result.return_code:
                fail_msg = (
                    "Failed to compile 'zstd' from source for use in Python interpreter extraction. " +
                    "'make' error message: {}".format(make_result.stderr)
                )
                fail(fail_msg)
            zstd = "{working_directory}/zstd".format(working_directory = working_directory)
            unzstd = "./unzstd"
            rctx.symlink(zstd, unzstd)

        exec_result = rctx.execute([
            which_with_fail("tar", rctx),
            "--extract",
            "--strip-components=2",
            "--use-compress-program={unzstd}".format(unzstd = unzstd),
            "--file={}".format(release_filename),
        ])
        if exec_result.return_code:
            fail_msg = (
                "Failed to extract Python interpreter from '{}'. ".format(release_filename) +
                "'tar' error message: {}".format(exec_result.stderr)
            )
            fail(fail_msg)
    else:
        rctx.download_and_extract(
            url = urls,
            sha256 = rctx.attr.sha256,
            stripPrefix = rctx.attr.strip_prefix,
            auth = auth,
        )

    patches = rctx.attr.patches
    if patches:
        for patch in patches:
            # Should take the strip as an attr, but this is fine for the moment
            rctx.patch(patch, strip = 1)

    # Write distutils.cfg to the Python installation.
    if "windows" in rctx.os.name:
        distutils_path = "Lib/distutils/distutils.cfg"
    else:
        distutils_path = "lib/python{}/distutils/distutils.cfg".format(python_short_version)
    if rctx.attr.distutils:
        rctx.file(distutils_path, rctx.read(rctx.attr.distutils))
    elif rctx.attr.distutils_content:
        rctx.file(distutils_path, rctx.attr.distutils_content)

    # Make the Python installation read-only.
    if not rctx.attr.ignore_root_user_error:
        if "windows" not in rctx.os.name:
            lib_dir = "lib" if "windows" not in platform else "Lib"

            exec_result = rctx.execute([which_with_fail("chmod", rctx), "-R", "ugo-w", lib_dir])
            if exec_result.return_code != 0:
                fail_msg = "Failed to make interpreter installation read-only. 'chmod' error msg: {}".format(
                    exec_result.stderr,
                )
                fail(fail_msg)
            exec_result = rctx.execute([which_with_fail("touch", rctx), "{}/.test".format(lib_dir)])
            if exec_result.return_code == 0:
                exec_result = rctx.execute([which_with_fail("id", rctx), "-u"])
                if exec_result.return_code != 0:
                    fail("Could not determine current user ID. 'id -u' error msg: {}".format(
                        exec_result.stderr,
                    ))
                uid = int(exec_result.stdout.strip())
                if uid == 0:
                    fail("The current user is root, please run as non-root when using the hermetic Python interpreter. See https://github.com/bazelbuild/rules_python/pull/713.")
                else:
                    fail("The current user has CAP_DAC_OVERRIDE set, please drop this capability when using the hermetic Python interpreter. See https://github.com/bazelbuild/rules_python/pull/713.")

    python_bin = "python.exe" if ("windows" in platform) else "bin/python3"

    glob_include = []
    glob_exclude = [
        "**/* *",  # Bazel does not support spaces in file names.
        # Unused shared libraries. `python` executable and the `:libpython` target
        # depend on `libpython{python_version}.so.1.0`.
        "lib/libpython{python_version}.so".format(python_version = python_short_version),
        # static libraries
        "lib/**/*.a",
        # tests for the standard libraries.
        "lib/python{python_version}/**/test/**".format(python_version = python_short_version),
        "lib/python{python_version}/**/tests/**".format(python_version = python_short_version),
        "**/__pycache__/*.pyc.*",  # During pyc creation, temp files named *.pyc.NNN are created
    ]

    if rctx.attr.ignore_root_user_error:
        glob_exclude += [
            # These pycache files are created on first use of the associated python files.
            # Exclude them from the glob because otherwise between the first time and second time a python toolchain is used,"
            # the definition of this filegroup will change, and depending rules will get invalidated."
            # See https://github.com/bazelbuild/rules_python/issues/1008 for unconditionally adding these to toolchains so we can stop ignoring them."
            "**/__pycache__/*.pyc",
            "**/__pycache__/*.pyo",
        ]

    if "windows" in platform:
        glob_include += [
            "*.exe",
            "*.dll",
            "bin/**",
            "DLLs/**",
            "extensions/**",
            "include/**",
            "Lib/**",
            "libs/**",
            "Scripts/**",
            "share/**",
            "tcl/**",
        ]
    else:
        glob_include += [
            "bin/**",
            "extensions/**",
            "include/**",
            "lib/**",
            "libs/**",
            "share/**",
        ]

    if rctx.attr.coverage_tool:
        if "windows" in rctx.os.name:
            coverage_tool = None
        else:
            coverage_tool = '"{}"'.format(rctx.attr.coverage_tool)

        coverage_attr_text = """\
    coverage_tool = select({{
        ":coverage_enabled": {coverage_tool},
        "//conditions:default": None
    }}),
""".format(coverage_tool = coverage_tool)
    else:
        coverage_attr_text = "    # coverage_tool attribute not supported by this Bazel version"

    build_content = """\
# Generated by python/repositories.bzl

load("@rules_python//python:py_runtime.bzl", "py_runtime")
load("@rules_python//python:py_runtime_pair.bzl", "py_runtime_pair")
load("@rules_python//python/cc:py_cc_toolchain.bzl", "py_cc_toolchain")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "files",
    srcs = glob(
        include = {glob_include},
        # Platform-agnostic filegroup can't match on all patterns.
        allow_empty = True,
        exclude = {glob_exclude},
    ),
)

cc_import(
    name = "interface",
    interface_library = "libs/python{python_version_nodot}.lib",
    system_provided = True,
)

filegroup(
    name = "includes",
    srcs = glob(["include/**/*.h"]),
)

cc_library(
    name = "python_headers",
    deps = select({{
        "@bazel_tools//src/conditions:windows": [":interface"],
        "//conditions:default": None,
    }}),
    hdrs = [":includes"],
    includes = [
        "include",
        "include/python{python_version}",
        "include/python{python_version}m",
    ],
)

cc_library(
    name = "libpython",
    hdrs = [":includes"],
    srcs = select({{
        "@platforms//os:windows": ["python3.dll", "libs/python{python_version_nodot}.lib"],
        "@platforms//os:macos": ["lib/libpython{python_version}.dylib"],
        "@platforms//os:linux": ["lib/libpython{python_version}.so", "lib/libpython{python_version}.so.1.0"],
    }}),
)

exports_files(["python", "{python_path}"])

# Used to only download coverage toolchain when the coverage is collected by
# bazel.
config_setting(
    name = "coverage_enabled",
    values = {{"collect_code_coverage": "true"}},
    visibility = ["//visibility:private"],
)

py_runtime(
    name = "py3_runtime",
    files = [":files"],
{coverage_attr}
    interpreter = "{python_path}",
    python_version = "PY3",
    bootstrap_template = "bootstrap_template.txt",
)

py_runtime_pair(
    name = "python_runtimes",
    py2_runtime = None,
    py3_runtime = ":py3_runtime",
)

py_cc_toolchain(
    name = "py_cc_toolchain",
    headers = ":python_headers",
    python_version = "{python_version}",
)
""".format(
        glob_exclude = repr(glob_exclude),
        glob_include = repr(glob_include),
        python_path = python_bin,
        python_version = python_short_version,
        python_version_nodot = python_short_version.replace(".", ""),
        coverage_attr = coverage_attr_text,
    )
    bootstrap_template_content = r"""%shebang%

# This script must retain compatibility with a wide variety of Python versions
# since it is run for every py_binary target. Currently we guarantee support
# going back to Python 2.7, and try to support even Python 2.6 on a best-effort
# basis. We might abandon 2.6 support once users have the ability to control the
# above shebang string via the Python toolchain (#8685).

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys

# The Python interpreter unconditionally prepends the directory containing this
# script (following symlinks) to the import path. This is the cause of #9239,
# and is a special case of #7091. We therefore explicitly delete that entry.
# TODO(#7091): Remove this hack when no longer necessary.
# del sys.path[0]

import os
import subprocess

def IsRunningFromZip():
  return %is_zipfile%

if IsRunningFromZip():
  import shutil
  import tempfile
  import zipfile
else:
  import re

# Return True if running on Windows
def IsWindows():
  return os.name == 'nt'

def GetWindowsPathWithUNCPrefix(path):
  path = path.strip()

  # No need to add prefix for non-Windows platforms.
  # And \\?\ doesn't work in python 2 or on mingw
  if not IsWindows() or sys.version_info[0] < 3:
    return path

  # Starting in Windows 10, version 1607(OS build 14393), MAX_PATH limitations have been
  # removed from common Win32 file and directory functions.
  # Related doc: https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=cmd#enable-long-paths-in-windows-10-version-1607-and-later
  import platform
  if platform.win32_ver()[1] >= '10.0.14393':
    return path

  # import sysconfig only now to maintain python 2.6 compatibility
  import sysconfig
  if sysconfig.get_platform() == 'mingw':
    return path

  # Lets start the unicode fun
  unicode_prefix = '\\\\?\\'
  if path.startswith(unicode_prefix):
    return path

  # os.path.abspath returns a normalized absolute path
  return unicode_prefix + os.path.abspath(path)

def HasWindowsExecutableExtension(path):
  return path.endswith('.exe') or path.endswith('.com') or path.endswith('.bat')

PYTHON_BINARY = '%python_binary%'
if IsWindows() and not HasWindowsExecutableExtension(PYTHON_BINARY):
  PYTHON_BINARY = PYTHON_BINARY + '.exe'

def SearchPath(name):
  search_path = os.getenv('PATH', os.defpath).split(os.pathsep)
  for directory in search_path:
    if directory:
      path = os.path.join(directory, name)
      if os.path.isfile(path) and os.access(path, os.X_OK):
        return path
  return None

def FindPythonBinary(module_space):
  return FindBinary(module_space, PYTHON_BINARY)

def PrintVerboseCoverage(*args):
  if os.environ.get("VERBOSE_COVERAGE"):
    print(*args, file=sys.stderr)

def FindCoverageEntryPoint(module_space):
  cov_tool = '%coverage_tool%'
  if cov_tool:
    PrintVerboseCoverage('Using toolchain coverage_tool %r' % cov_tool)
  else:
    cov_tool = os.environ.get('PYTHON_COVERAGE')
    if cov_tool:
      PrintVerboseCoverage('PYTHON_COVERAGE: %r' % cov_tool)
  if cov_tool:
    return FindBinary(module_space, cov_tool)
  return None

def FindBinary(module_space, bin_name):
  if not bin_name:
    return None
  if bin_name.startswith("//"):
    # Case 1: Path is a label. Not supported yet.
    raise AssertionError(
        "Bazel does not support execution of Python interpreters via labels yet"
    )
  elif os.path.isabs(bin_name):
    # Case 2: Absolute path.
    return bin_name
  # Use normpath() to convert slashes to os.sep on Windows.
  elif os.sep in os.path.normpath(bin_name):
    # Case 3: Path is relative to the repo root.
    return os.path.join(module_space, bin_name)
  else:
    # Case 4: Path has to be looked up in the search path.
    return SearchPath(bin_name)

def CreatePythonPathEntries(python_imports, module_space):
  parts = python_imports.split(':')
  return [module_space] + ['%s/%s' % (module_space, path) for path in parts]

def FindModuleSpace(main_rel_path):
  # When the calling process used the runfiles manifest to resolve the
  # location of this stub script, the path may be expanded. This means
  # argv[0] may no longer point to a location inside the runfiles
  # directory. We should therefore respect RUNFILES_DIR and
  # RUNFILES_MANIFEST_FILE set by the caller.
  runfiles_dir = os.environ.get('RUNFILES_DIR', None)
  if not runfiles_dir:
    runfiles_manifest_file = os.environ.get('RUNFILES_MANIFEST_FILE', '')
    if (runfiles_manifest_file.endswith('.runfiles_manifest') or
        runfiles_manifest_file.endswith('.runfiles/MANIFEST')):
      runfiles_dir = runfiles_manifest_file[:-9]
  # Be defensive: the runfiles dir should contain our main entry point. If
  # it doesn't, then it must not be our runfiles directory.
  if runfiles_dir and os.path.exists(os.path.join(runfiles_dir, main_rel_path)):
    return runfiles_dir

  stub_filename = sys.argv[0]
  if not os.path.isabs(stub_filename):
    stub_filename = os.path.join(os.getcwd(), stub_filename)

  while True:
    module_space = stub_filename + ('.exe' if IsWindows() else '') + '.runfiles'
    if os.path.isdir(module_space):
      return module_space

    runfiles_pattern = r'(.*\.runfiles)' + (r'\\' if IsWindows() else '/') + '.*'
    matchobj = re.match(runfiles_pattern, stub_filename)
    if matchobj:
      return matchobj.group(1)

    if not os.path.islink(stub_filename):
      break
    target = os.readlink(stub_filename)
    if os.path.isabs(target):
      stub_filename = target
    else:
      stub_filename = os.path.join(os.path.dirname(stub_filename), target)

  raise AssertionError('Cannot find .runfiles directory for %s' % sys.argv[0])

def ExtractZip(zip_path, dest_dir):
  zip_path = GetWindowsPathWithUNCPrefix(zip_path)
  dest_dir = GetWindowsPathWithUNCPrefix(dest_dir)
  with zipfile.ZipFile(zip_path) as zf:
    for info in zf.infolist():
      zf.extract(info, dest_dir)
      # UNC-prefixed paths must be absolute/normalized. See
      # https://docs.microsoft.com/en-us/windows/desktop/fileio/naming-a-file#maximum-path-length-limitation
      file_path = os.path.abspath(os.path.join(dest_dir, info.filename))
      # The Unix st_mode bits (see "man 7 inode") are stored in the upper 16
      # bits of external_attr. Of those, we set the lower 12 bits, which are the
      # file mode bits (since the file type bits can't be set by chmod anyway).
      attrs = info.external_attr >> 16
      if attrs != 0:  # Rumor has it these can be 0 for zips created on Windows.
        os.chmod(file_path, attrs & 0o7777)

# Create the runfiles tree by extracting the zip file
def CreateModuleSpace():
  temp_dir = tempfile.mkdtemp('', 'Bazel.runfiles_')
  ExtractZip(os.path.dirname(__file__), temp_dir)
  # IMPORTANT: Later code does `rm -fr` on dirname(module_space) -- it's
  # important that deletion code be in sync with this directory structure
  return os.path.join(temp_dir, 'runfiles')

# Returns repository roots to add to the import path.
def GetRepositoriesImports(module_space, import_all):
  if import_all:
    repo_dirs = [os.path.join(module_space, d) for d in os.listdir(module_space)]
    repo_dirs.sort()
    return [d for d in repo_dirs if os.path.isdir(d)]
  return [os.path.join(module_space, '%workspace_name%')]

def RunfilesEnvvar(module_space):
  # If this binary is the data-dependency of another one, the other sets
  # RUNFILES_MANIFEST_FILE or RUNFILES_DIR for our sake.
  runfiles = os.environ.get('RUNFILES_MANIFEST_FILE', None)
  if runfiles:
    return ('RUNFILES_MANIFEST_FILE', runfiles)

  runfiles = os.environ.get('RUNFILES_DIR', None)
  if runfiles:
    return ('RUNFILES_DIR', runfiles)

  # If running from a zip, there's no manifest file.
  if IsRunningFromZip():
    return ('RUNFILES_DIR', module_space)

  # Look for the runfiles "output" manifest, argv[0] + ".runfiles_manifest"
  runfiles = module_space + '_manifest'
  if os.path.exists(runfiles):
    return ('RUNFILES_MANIFEST_FILE', runfiles)

  # Look for the runfiles "input" manifest, argv[0] + ".runfiles/MANIFEST"
  # Normally .runfiles_manifest and MANIFEST are both present, but the
  # former will be missing for zip-based builds or if someone copies the
  # runfiles tree elsewhere.
  runfiles = os.path.join(module_space, 'MANIFEST')
  if os.path.exists(runfiles):
    return ('RUNFILES_MANIFEST_FILE', runfiles)

  # If running in a sandbox and no environment variables are set, then
  # Look for the runfiles  next to the binary.
  if module_space.endswith('.runfiles') and os.path.isdir(module_space):
    return ('RUNFILES_DIR', module_space)

  return (None, None)

def Deduplicate(items):
  seen = set()
  for it in items:
      if it not in seen:
          seen.add(it)
          yield it

def InstrumentedFilePaths():
  manifest_filename = os.environ.get('COVERAGE_MANIFEST')
  if not manifest_filename:
    return
  with open(manifest_filename, "r") as manifest:
    for line in manifest:
      filename = line.strip()
      if not filename:
        continue
      try:
        realpath = os.path.realpath(filename)
      except OSError:
        print(
          "Could not find instrumented file {}".format(filename),
          file=sys.stderr)
        continue
      if realpath != filename:
        PrintVerboseCoverage("Fixing up {} -> {}".format(realpath, filename))
        yield (realpath, filename)

def UnresolveSymlinks(output_filename):
  # type: (str) -> None
  substitutions = list(InstrumentedFilePaths())
  if substitutions:
    unfixed_file = output_filename + '.tmp'
    os.rename(output_filename, unfixed_file)
    with open(unfixed_file, "r") as unfixed:
      with open(output_filename, "w") as output_file:
        for line in unfixed:
          if line.startswith('SF:'):
            for (realpath, filename) in substitutions:
              line = line.replace(realpath, filename)
          output_file.write(line)
    os.unlink(unfixed_file)

def ExecuteFile(python_program, main_filename, args, env, module_space,
                coverage_entrypoint, workspace, delete_module_space):
  # type: (str, str, list[str], dict[str, str], str, str|None, str|None) -> ...
  # We want to use os.execv instead of subprocess.call, which causes
  # problems with signal passing (making it difficult to kill
  # Bazel). However, these conditions force us to run via
  # subprocess.call instead:
  #
  # - On Windows, os.execv doesn't handle arguments with spaces
  #   correctly, and it actually starts a subprocess just like
  #   subprocess.call.
  # - When running in a workspace or zip file, we need to clean up the
  #   workspace after the process finishes so control must return here.
  # - If we may need to emit a host config warning after execution, we
  #   can't execv because we need control to return here. This only
  #   happens for targets built in the host config.
  # - For coverage targets, at least coveragepy requires running in
  #   two invocations, which also requires control to return here.
  #
  if not (IsWindows() or workspace or coverage_entrypoint or delete_module_space):
    _RunExecv(python_program, main_filename, args, env)

  if coverage_entrypoint is not None:
    ret_code = _RunForCoverage(python_program, main_filename, args, env,
                               coverage_entrypoint, workspace)
  else:
    ret_code = subprocess.call(
      [python_program, main_filename] + args,
      env=env,
      cwd=workspace
    )

  if delete_module_space:
    # NOTE: dirname() is called because CreateModuleSpace() creates a
    # sub-directory within a temporary directory, and we want to remove the
    # whole temporary directory.
    shutil.rmtree(os.path.dirname(module_space), True)
  sys.exit(ret_code)

def _RunExecv(python_program, main_filename, args, env):
  # type: (str, str, list[str], dict[str, str]) -> ...
  os.environ.update(env)
  os.execv(python_program, [python_program, main_filename] + args)

def _RunForCoverage(python_program, main_filename, args, env,
                    coverage_entrypoint, workspace):
  # type: (str, str, list[str], dict[str, str], str, str|None) -> int
  # We need for coveragepy to use relative paths.  This can only be configured
  # via an rc file, so we need to make one.
  rcfile_name = os.path.join(os.environ['COVERAGE_DIR'], '.coveragerc')
  with open(rcfile_name, "w") as rcfile:
    rcfile.write('''[run]
relative_files = True
''')
  PrintVerboseCoverage('Coverage entrypoint:', coverage_entrypoint)
  # First run the target Python file via coveragepy to create a .coverage
  # database file, from which we can later export lcov.
  ret_code = subprocess.call(
    [
      python_program,
      coverage_entrypoint,
      "run",
      "--rcfile=" + rcfile_name,
      "--append",
      "--branch",
      main_filename
    ] + args,
    env=env,
    cwd=workspace
  )
  output_filename = os.path.join(os.environ['COVERAGE_DIR'], 'pylcov.dat')

  PrintVerboseCoverage('Converting coveragepy database to lcov:', output_filename)
  # Run coveragepy again to convert its .coverage database file into lcov.
  ret_code = subprocess.call(
    [
      python_program,
      coverage_entrypoint,
      "lcov",
      "--rcfile=" + rcfile_name,
      "-o",
      output_filename
    ],
    env=env,
    cwd=workspace
  ) or ret_code
  try:
    os.unlink(rcfile_name)
  except OSError as err:
    # It's possible that the profiled program might execute another Python
    # binary through a wrapper that would then delete the rcfile.  Not much
    # we can do about that, besides ignore the failure here.
    PrintVerboseCoverage('Error removing temporary coverage rc file:', err)
  if os.path.isfile(output_filename):
    UnresolveSymlinks(output_filename)
  return ret_code

def Main():
  args = sys.argv[1:]

  new_env = {}

  # The main Python source file.
  # The magic string percent-main-percent is replaced with the runfiles-relative
  # filename of the main file of the Python binary in BazelPythonSemantics.java.
  main_rel_path = '%main%'
  if IsWindows():
    main_rel_path = main_rel_path.replace('/', os.sep)

  if IsRunningFromZip():
    module_space = CreateModuleSpace()
    delete_module_space = True
  else:
    module_space = FindModuleSpace(main_rel_path)
    delete_module_space = False

  python_imports = '%imports%'
  python_path_entries = CreatePythonPathEntries(python_imports, module_space)
  python_path_entries += GetRepositoriesImports(module_space, %import_all%)
  # Remove duplicates to avoid overly long PYTHONPATH (#10977). Preserve order,
  # keep first occurrence only.
  python_path_entries = [
    GetWindowsPathWithUNCPrefix(d)
    for d in python_path_entries
  ]

  old_python_path = os.environ.get('PYTHONPATH')
  if old_python_path:
    python_path_entries += old_python_path.split(os.pathsep)

  python_path = os.pathsep.join(Deduplicate(python_path_entries))

  if IsWindows():
    python_path = python_path.replace('/', os.sep)

  new_env['PYTHONPATH'] = python_path
  runfiles_envkey, runfiles_envvalue = RunfilesEnvvar(module_space)
  if runfiles_envkey:
    new_env[runfiles_envkey] = runfiles_envvalue

  # Don't prepend a potentially unsafe path to sys.path
  # See: https://docs.python.org/3.11/using/cmdline.html#envvar-PYTHONSAFEPATH
  new_env['PYTHONSAFEPATH'] = '1'

  main_filename = os.path.join(module_space, main_rel_path)
  main_filename = GetWindowsPathWithUNCPrefix(main_filename)
  assert os.path.exists(main_filename), \
         'Cannot exec() %r: file not found.' % main_filename
  assert os.access(main_filename, os.R_OK), \
         'Cannot exec() %r: file not readable.' % main_filename

  program = python_program = FindPythonBinary(module_space)
  if python_program is None:
    raise AssertionError('Could not find python binary: ' + PYTHON_BINARY)

  # COVERAGE_DIR is set if coverage is enabled and instrumentation is configured
  # for something, though it could be another program executing this one or
  # one executed by this one (e.g. an extension module).
  if os.environ.get('COVERAGE_DIR'):
    cov_tool = FindCoverageEntryPoint(module_space)
    if cov_tool is None:
      PrintVerboseCoverage('Coverage was enabled, but python coverage tool was not configured.')
    else:
      # Inhibit infinite recursion:
      if 'PYTHON_COVERAGE' in os.environ:
        del os.environ['PYTHON_COVERAGE']

      if not os.path.exists(cov_tool):
        raise EnvironmentError(
          'Python coverage tool %r not found. '
          'Try running with VERBOSE_COVERAGE=1 to collect more information.'
          % cov_tool
        )

      # coverage library expects sys.path[0] to contain the library, and replaces
      # it with the directory of the program it starts. Our actual sys.path[0] is
      # the runfiles directory, which must not be replaced.
      # CoverageScript.do_execute() undoes this sys.path[0] setting.
      #
      # Update sys.path such that python finds the coverage package. The coverage
      # entry point is coverage.coverage_main, so we need to do twice the dirname.
      python_path_entries = new_env['PYTHONPATH'].split(os.pathsep)
      python_path_entries.append(os.path.dirname(os.path.dirname(cov_tool)))
      new_env['PYTHONPATH'] = os.pathsep.join(Deduplicate(python_path_entries))
  else:
    cov_tool = None

  new_env.update((key, val) for key, val in os.environ.items() if key not in new_env)

  workspace = None
  if IsRunningFromZip():
    # If RUN_UNDER_RUNFILES equals 1, it means we need to
    # change directory to the right runfiles directory.
    # (So that the data files are accessible)
    if os.environ.get('RUN_UNDER_RUNFILES') == '1':
      workspace = os.path.join(module_space, '%workspace_name%')

  try:
    sys.stdout.flush()
    # NOTE: ExecuteFile may call execve() and lines after this will never run.
    ExecuteFile(
      python_program, main_filename, args, new_env, module_space,
      cov_tool, workspace,
      delete_module_space = delete_module_space,
    )

  except EnvironmentError:
    # This works from Python 2.4 all the way to 3.x.
    e = sys.exc_info()[1]
    # This exception occurs when os.execv() fails for some reason.
    if not getattr(e, 'filename', None):
      e.filename = program  # Add info to error message
    raise

if __name__ == '__main__':
  Main()
"""
    rctx.delete("python")
    rctx.symlink(python_bin, "python")
    rctx.file(STANDALONE_INTERPRETER_FILENAME, "# File intentionally left blank. Indicates that this is an interpreter repo created by rules_python.")
    rctx.file("BUILD.bazel", build_content)
    rctx.file("bootstrap_template.txt", bootstrap_template_content)

    attrs = {
        "auth_patterns": rctx.attr.auth_patterns,
        "coverage_tool": rctx.attr.coverage_tool,
        "distutils": rctx.attr.distutils,
        "distutils_content": rctx.attr.distutils_content,
        "ignore_root_user_error": rctx.attr.ignore_root_user_error,
        "name": rctx.attr.name,
        "netrc": rctx.attr.netrc,
        "patches": rctx.attr.patches,
        "platform": platform,
        "python_version": python_version,
        "release_filename": release_filename,
        "sha256": rctx.attr.sha256,
        "strip_prefix": rctx.attr.strip_prefix,
    }

    if rctx.attr.url:
        attrs["url"] = rctx.attr.url
    else:
        attrs["urls"] = urls

    return attrs

python_repository = repository_rule(
    _python_repository_impl,
    doc = "Fetches the external tools needed for the Python toolchain.",
    attrs = {
        "auth_patterns": attr.string_dict(
            doc = "Override mapping of hostnames to authorization patterns; mirrors the eponymous attribute from http_archive",
        ),
        "coverage_tool": attr.string(
            # Mirrors the definition at
            # https://github.com/bazelbuild/bazel/blob/master/src/main/starlark/builtins_bzl/common/python/py_runtime_rule.bzl
            doc = """
This is a target to use for collecting code coverage information from `py_binary`
and `py_test` targets.

If set, the target must either produce a single file or be an executable target.
The path to the single file, or the executable if the target is executable,
determines the entry point for the python coverage tool.  The target and its
runfiles will be added to the runfiles when coverage is enabled.

The entry point for the tool must be loadable by a Python interpreter (e.g. a
`.py` or `.pyc` file).  It must accept the command line arguments
of coverage.py (https://coverage.readthedocs.io), at least including
the `run` and `lcov` subcommands.

The target is accepted as a string by the python_repository and evaluated within
the context of the toolchain repository.

For more information see the official bazel docs
(https://bazel.build/reference/be/python#py_runtime.coverage_tool).
""",
        ),
        "distutils": attr.label(
            allow_single_file = True,
            doc = "A distutils.cfg file to be included in the Python installation. " +
                  "Either distutils or distutils_content can be specified, but not both.",
            mandatory = False,
        ),
        "distutils_content": attr.string(
            doc = "A distutils.cfg file content to be included in the Python installation. " +
                  "Either distutils or distutils_content can be specified, but not both.",
            mandatory = False,
        ),
        "ignore_root_user_error": attr.bool(
            default = False,
            doc = "Whether the check for root should be ignored or not. This causes cache misses with .pyc files.",
            mandatory = False,
        ),
        "netrc": attr.string(
            doc = ".netrc file to use for authentication; mirrors the eponymous attribute from http_archive",
        ),
        "patches": attr.label_list(
            doc = "A list of patch files to apply to the unpacked interpreter",
            mandatory = False,
        ),
        "platform": attr.string(
            doc = "The platform name for the Python interpreter tarball.",
            mandatory = True,
            values = PLATFORMS.keys(),
        ),
        "python_version": attr.string(
            doc = "The Python version.",
            mandatory = True,
        ),
        "release_filename": attr.string(
            doc = "The filename of the interpreter to be downloaded",
            mandatory = True,
        ),
        "sha256": attr.string(
            doc = "The SHA256 integrity hash for the Python interpreter tarball.",
            mandatory = True,
        ),
        "strip_prefix": attr.string(
            doc = "A directory prefix to strip from the extracted files.",
        ),
        "url": attr.string(
            doc = "The URL of the interpreter to download. Exactly one of url and urls must be set.",
        ),
        "urls": attr.string_list(
            doc = "The URL of the interpreter to download. Exactly one of url and urls must be set.",
        ),
        "zstd_sha256": attr.string(
            default = "7c42d56fac126929a6a85dbc73ff1db2411d04f104fae9bdea51305663a83fd0",
        ),
        "zstd_url": attr.string(
            default = "https://github.com/facebook/zstd/releases/download/v{version}/zstd-{version}.tar.gz",
        ),
        "zstd_version": attr.string(
            default = "1.5.2",
        ),
    },
)

# Wrapper macro around everything above, this is the primary API.
def python_register_toolchains(
        name,
        python_version,
        distutils = None,
        distutils_content = None,
        register_toolchains = True,
        register_coverage_tool = False,
        set_python_version_constraint = False,
        tool_versions = TOOL_VERSIONS,
        **kwargs):
    """Convenience macro for users which does typical setup.

    - Create a repository for each built-in platform like "python_linux_amd64" -
      this repository is lazily fetched when Python is needed for that platform.
    - Create a repository exposing toolchains for each platform like
      "python_platforms".
    - Register a toolchain pointing at each platform.
    Users can avoid this macro and do these steps themselves, if they want more
    control.
    Args:
        name: base name for all created repos, like "python38".
        python_version: the Python version.
        distutils: see the distutils attribute in the python_repository repository rule.
        distutils_content: see the distutils_content attribute in the python_repository repository rule.
        register_toolchains: Whether or not to register the downloaded toolchains.
        register_coverage_tool: Whether or not to register the downloaded coverage tool to the toolchains.
            NOTE: Coverage support using the toolchain is only supported in Bazel 6 and higher.

        set_python_version_constraint: When set to true, target_compatible_with for the toolchains will include a version constraint.
        tool_versions: a dict containing a mapping of version with SHASUM and platform info. If not supplied, the defaults
            in python/versions.bzl will be used.
        **kwargs: passed to each python_repositories call.
    """

    if BZLMOD_ENABLED:
        # you cannot used native.register_toolchains when using bzlmod.
        register_toolchains = False

    base_url = kwargs.pop("base_url", DEFAULT_RELEASE_BASE_URL)

    python_version = full_version(python_version)

    toolchain_repo_name = "{name}_toolchains".format(name = name)

    # When using unreleased Bazel versions, the version is an empty string
    if native.bazel_version:
        bazel_major = int(native.bazel_version.split(".")[0])
        if bazel_major < 6:
            if register_coverage_tool:
                # buildifier: disable=print
                print((
                    "WARNING: ignoring register_coverage_tool=True when " +
                    "registering @{name}: Bazel 6+ required, got {version}"
                ).format(
                    name = name,
                    version = native.bazel_version,
                ))
            register_coverage_tool = False

    loaded_platforms = []
    for platform in PLATFORMS.keys():
        sha256 = tool_versions[python_version]["sha256"].get(platform, None)
        if not sha256:
            continue

        loaded_platforms.append(platform)
        (release_filename, urls, strip_prefix, patches) = get_release_info(platform, python_version, base_url, tool_versions)

        # allow passing in a tool version
        coverage_tool = None
        coverage_tool = tool_versions[python_version].get("coverage_tool", {}).get(platform, None)
        if register_coverage_tool and coverage_tool == None:
            coverage_tool = coverage_dep(
                name = "{name}_{platform}_coverage".format(
                    name = name,
                    platform = platform,
                ),
                python_version = python_version,
                platform = platform,
                visibility = ["@{name}_{platform}//:__subpackages__".format(
                    name = name,
                    platform = platform,
                )],
            )

        python_repository(
            name = "{name}_{platform}".format(
                name = name,
                platform = platform,
            ),
            sha256 = sha256,
            patches = patches,
            platform = platform,
            python_version = python_version,
            release_filename = release_filename,
            urls = urls,
            distutils = distutils,
            distutils_content = distutils_content,
            strip_prefix = strip_prefix,
            coverage_tool = coverage_tool,
            **kwargs
        )
        if register_toolchains:
            native.register_toolchains("@{toolchain_repo_name}//:{platform}_toolchain".format(
                toolchain_repo_name = toolchain_repo_name,
                platform = platform,
            ))
            native.register_toolchains("@{toolchain_repo_name}//:{platform}_py_cc_toolchain".format(
                toolchain_repo_name = toolchain_repo_name,
                platform = platform,
            ))

    toolchain_aliases(
        name = name,
        python_version = python_version,
        user_repository_name = name,
        platforms = loaded_platforms,
    )

    # in bzlmod we write out our own toolchain repos
    if BZLMOD_ENABLED:
        return

    toolchains_repo(
        name = toolchain_repo_name,
        python_version = python_version,
        set_python_version_constraint = set_python_version_constraint,
        user_repository_name = name,
    )

def python_register_multi_toolchains(
        name,
        python_versions,
        default_version = None,
        **kwargs):
    """Convenience macro for registering multiple Python toolchains.

    Args:
        name: base name for each name in python_register_toolchains call.
        python_versions: the Python version.
        default_version: the default Python version. If not set, the first version in
            python_versions is used.
        **kwargs: passed to each python_register_toolchains call.
    """
    if len(python_versions) == 0:
        fail("python_versions must not be empty")

    if not default_version:
        default_version = python_versions.pop(0)
    for python_version in python_versions:
        if python_version == default_version:
            # We register the default version lastly so that it's not picked first when --platforms
            # is set with a constraint during toolchain resolution. This is due to the fact that
            # Bazel will match the unconstrained toolchain if we register it before the constrained
            # ones.
            continue
        python_register_toolchains(
            name = name + "_" + python_version.replace(".", "_"),
            python_version = python_version,
            set_python_version_constraint = True,
            **kwargs
        )
    python_register_toolchains(
        name = name + "_" + default_version.replace(".", "_"),
        python_version = default_version,
        set_python_version_constraint = False,
        **kwargs
    )

    multi_toolchain_aliases(
        name = name,
        python_versions = {
            python_version: name + "_" + python_version.replace(".", "_")
            for python_version in (python_versions + [default_version])
        },
    )
