# rules_python Changelog

This is a human-friendly changelog in a keepachangelog.com style format.
Because this changelog is for end-user consumption of meaningful changes,only
a summary of a release's changes is described. This means every commit is not
necessarily mentioned, and internal refactors or code cleanups are omitted
unless they're particularly notable.

A brief description of the categories of changes:

* `Changed`: Some behavior changed. If the change is expected to break a
  public API or supported behavior, it will be marked as **BREAKING**. Note that
  beta APIs will not have breaking API changes called out.
* `Fixed`: A bug, or otherwise incorrect behavior, was fixed.
* `Added`: A new feature, API, or behavior was added in a backwards compatible
  manner.
* Particular sub-systems are identified using parentheses, e.g. `(bzlmod)` or
  `(docs)`.

## Unreleased

### Changed

* (runfiles) `rules_python.python.runfiles` now directly implements type hints
  and drops support for python2 as a result.

* (toolchains) `py_runtime`, `py_runtime_pair`, and `PyRuntimeInfo` now use the
  rules_python Starlark implementation, not the one built into Bazel. NOTE: This
  only applies to Bazel 6+; Bazel 5 still uses the builtin implementation.

* (pip_parse) The parameter `experimental_requirement_cycles` may be provided a
  map of names to lists of requirements which form a dependency
  cycle. `pip_parse` will break the cycle for you transparently. This behavior
  is also available under bzlmod as
  `pip.parse(experimental_requirement_cycles={})`.

* (pip_install) the deprecated `pip_install` macro and related items have been
  removed.

* (toolchains) `py_runtime` can now take an executable target. Note: runfiles
  from the target are not supported yet.

### Fixed

* (gazelle) The gazelle plugin helper was not working with Python toolchains 3.11
  and above due to a bug in the helper components not being on PYTHONPATH.

* (pip_parse) The repositories created by `whl_library` can now parse the `whl`
  METADATA and generate dependency closures irrespective of the host platform
  the generation is executed on. This can be turned on by supplying
  `experimental_target_platforms = ["all"]` to the `pip_parse` or the `bzlmod`
  equivalent. This may help in cases where fetching wheels for a different
  platform using `download_only = True` feature.
* (bzlmod pip.parse) The `pip.parse(python_interpreter)` arg now works for
  specifying a local system interpreter.
* (bzlmod pip.parse) Requirements files with duplicate entries for the same
  package (e.g. one for the package, one for an extra) now work.
* (bzlmod python.toolchain) Submodules can now (re)register the Python version
  that rules_python has set as the default.
  ([#1638](https://github.com/bazelbuild/rules_python/issues/1638))
* (whl_library) Actually use the provided patches to patch the whl_library.
  On Windows the patching may result in files with CRLF line endings, as a result
  the RECORD file consistency requirement is lifted and now a warning is emitted
  instead with a location to the patch that could be used to silence the warning.
  Copy the patch to your workspace and add it to the list if patches for the wheel
  file if you decide to do so.
* (coverage): coverage reports are now created when the version-aware
  rules are used.
  ([#1600](https://github.com/bazelbuild/rules_python/issues/1600))
* (toolchains) Workspace builds register the py cc toolchain (bzlmod already
  was). This makes e.g. `//python/cc:current_py_cc_headers` Just Work.
  ([#1669](https://github.com/bazelbuild/rules_python/issues/1669))

### Added

* (docs) bzlmod extensions are now documented on rules-python.readthedocs.io
* (gazelle) `file` generation mode can now also add `__init__.py` to the srcs
  attribute for every target in the package. This is enabled through a separate
  directive `python_generation_mode_per_file_include_init`.

[0.XX.0]: https://github.com/bazelbuild/rules_python/releases/tag/0.XX.0

## [0.27.0] - 2023-11-16

[0.27.0]: https://github.com/bazelbuild/rules_python/releases/tag/0.27.0

### Changed

* Make `//python/pip_install:pip_repository_bzl` `bzl_library` target internal
  as all of the publicly available symbols (etc. `package_annotation`) are
  re-exported via `//python:pip_bzl` `bzl_library`.

* (gazelle) Gazelle Python extension no longer has runtime dependencies. Using
  `GAZELLE_PYTHON_RUNTIME_DEPS` from `@rules_python_gazelle_plugin//:def.bzl` is
  no longer necessary.

* (pip_parse) The installation of `pip_parse` repository rule toolchain
  dependencies is now done as part of `py_repositories` call.

* (pip_parse) The generated `requirements.bzl` file now has an additional symbol
  `all_whl_requirements_by_package` which provides a map from the normalized
  PyPI package name to the target that provides the built wheel file. Use
  `pip_utils.normalize_name` function from `@rules_python//python:pip.bzl` to
  convert a PyPI package name to a key in the `all_whl_requirements_by_package`
  map.

* (pip_parse) The flag `incompatible_generate_aliases` has been flipped to
  `True` by default on `non-bzlmod` setups allowing users to use the same label
  strings during the transition period. For example, instead of
  `@pypi_foo//:pkg`, you can now use `@pypi//foo` or `@pypi//foo:pkg`. Other
  labels that are present in the `foo` package are `dist_info`, `whl` and
  `data`. Note, that the `@pypi_foo//:pkg` labels are still present for
  backwards compatibility.

* (gazelle) The flag `use_pip_repository_aliases` is now set to `True` by
  default, which will cause `gazelle` to change third-party dependency labels
  from `@pip_foo//:pkg` to `@pip//foo` by default.

* The `compile_pip_requirements` now defaults to `pyproject.toml` if the `src`
  or `requirements_in` attributes are unspecified, matching the upstream
  `pip-compile` behaviour more closely.

* (gazelle) Use relative paths if possible for dependencies added through
  the use of the `resolve` directive.

* (gazelle) When using `python_generation_mode file`, one `py_test` target is
  made per test file even if a target named `__test__` or a file named
  `__test__.py` exists in the same package. Previously in these cases there
  would only be one test target made.

Breaking changes:

* (pip) `pip_install` repository rule in this release has been disabled and
  will fail by default. The API symbol is going to be removed in the next
  version, please migrate to `pip_parse` as a replacement. The `pip_parse`
  rule no longer supports `requirements` attribute, please use
  `requirements_lock` instead.

* (py_wheel) switch `incompatible_normalize_name` and
  `incompatible_normalize_version` to `True` by default to enforce `PEP440`
  for wheel names built by `rules_python`.

* (tools/wheelmaker.py) drop support for Python 2 as only Python 3 is tested.

### Fixed

* Skip aliases for unloaded toolchains. Some Python versions that don't have full
  platform support, and referencing their undefined repositories can break operations
  like `bazel query rdeps(...)`.

* Python code generated from `proto_library` with `strip_import_prefix` can be imported now.

* (py_wheel) Produce deterministic wheel files and make `RECORD` file entries
  follow the order of files written to the `.whl` archive.

* (gazelle) Generate a single `py_test` target when `gazelle:python_generation_mode project`
  is used.

* (gazelle) Move waiting for the Python interpreter process to exit to the shutdown hook
  to make the usage of the `exec.Command` more idiomatic.

* (toolchains) Keep tcl subdirectory in Windows build of hermetic interpreter.

* (bzlmod) sub-modules now don't have the `//conditions:default` clause in the
  hub repos created by `pip.parse`. This should fix confusing error messages
  in case there is a misconfiguration of toolchains or a bug in `rules_python`.

### Added

* (bzlmod) Added `.whl` patching support via `patches` and `patch_strip`
  arguments to the new `pip.override` tag class.

* (pip) Support for using [PEP621](https://peps.python.org/pep-0621/) compliant
  `pyproject.toml` for creating a resolved `requirements.txt` file.

* (utils) Added a `pip_utils` struct with a `normalize_name` function to allow users
  to find out how `rules_python` would normalize a PyPI distribution name.

[0.27.0]: https://github.com/bazelbuild/rules_python/releases/tag/0.27.0

## [0.26.0] - 2023-10-06

### Changed

* Python version patch level bumps:
  * 3.8.15  -> 3.8.18
  * 3.9.17  -> 3.9.18
  * 3.10.12 -> 3.10.13
  * 3.11.4  -> 3.11.6

* (deps) Upgrade rules_go 0.39.1 -> 0.41.0; this is so gazelle integration works with upcoming Bazel versions

* (multi-version) The `distribs` attribute is no longer propagated. This
  attribute has been long deprecated by Bazel and shouldn't be used.

* Calling `//python:repositories.bzl#py_repositories()` is required. It has
  always been documented as necessary, but it was possible to omit it in certain
  cases. An error about `@rules_python_internal` means the `py_repositories()`
  call is missing in `WORKSPACE`.

* (bzlmod) The `pip.parse` extension will generate os/arch specific lock
  file entries on `bazel>=6.4`.


### Added

* (bzlmod, entry_point) Added
  [`py_console_script_binary`](./docs/py_console_script_binary.md), which
  allows adding custom dependencies to a package's entry points and customizing
  the `py_binary` rule used to build it.

* New Python versions available: `3.8.17`, `3.11.5` using
  https://github.com/indygreg/python-build-standalone/releases/tag/20230826.

* (gazelle) New `# gazelle:python_generation_mode file` directive to support
  generating one `py_library` per file.

* (python_repository) Support `netrc` and `auth_patterns` attributes to enable
  authentication against private HTTP hosts serving Python toolchain binaries.

* `//python:packaging_bzl` added, a `bzl_library` for the Starlark
  files `//python:packaging.bzl` requires.
* (py_wheel) Added the `incompatible_normalize_name` feature flag to
  normalize the package distribution name according to latest Python
  packaging standards. Defaults to `False` for the time being.
* (py_wheel) Added the `incompatible_normalize_version` feature flag
  to normalize the package version according to PEP440 standard. This
  also adds support for local version specifiers (versions with a `+`
  in them), in accordance with PEP440. Defaults to `False` for the
  time being.

* New Python versions available: `3.8.18`, `3.9.18`, `3.10.13`, `3.11.6`, `3.12.0` using
  https://github.com/indygreg/python-build-standalone/releases/tag/20231002.
  `3.12.0` support is considered beta and may have issues.

### Removed

* (bzlmod) The `entry_point` macro is no longer supported and has been removed
  in favour of the `py_console_script_binary` macro for `bzlmod` users.

* (bzlmod) The `pip.parse` no longer generates `{hub_name}_{py_version}` hub repos
  as the `entry_point` macro has been superseded by `py_console_script_binary`.

* (bzlmod) The `pip.parse` no longer generates `{hub_name}_{distribution}` hub repos.

### Fixed

* (whl_library) No longer restarts repository rule when fetching external
  dependencies improving initial build times involving external dependency
  fetching.

* (gazelle) Improve runfiles lookup hermeticity.

[0.26.0]: https://github.com/bazelbuild/rules_python/releases/tag/0.26.0

## [0.25.0] - 2023-08-22

### Changed

* Python version patch level bumps:
  * 3.9.16 -> 3.9.17
  * 3.10.9 -> 3.10.12
  * 3.11.1 -> 3.11.4
* (bzlmod) `pip.parse` can no longer automatically use the default
  Python version; this was an unreliable and unsafe behavior. The
  `python_version` arg must always be explicitly specified.

### Fixed

* (docs) Update docs to use correct bzlmod APIs and clarify how and when to use
  various APIs.
* (multi-version) The `main` arg is now correctly computed and usually optional.
* (bzlmod) `pip.parse` no longer requires a call for whatever the configured
  default Python version is.

### Added

* Created a changelog.
* (gazelle) Stop generating unnecessary imports.
* (toolchains) s390x supported for Python 3.9.17, 3.10.12, and 3.11.4.

[0.25.0]: https://github.com/bazelbuild/rules_python/releases/tag/0.25.0

## [0.24.0] - 2023-07-11

### Changed

* **BREAKING** (gazelle) Gazelle 0.30.0 or higher is required
* (bzlmod) `@python_aliases` renamed to `@python_versions
* (bzlmod) `pip.parse` arg `name` renamed to `hub_name`
* (bzlmod) `pip.parse` arg `incompatible_generate_aliases` removed and always
  true.

### Fixed

* (bzlmod) Fixing Windows Python Interpreter symlink issues
* (py_wheel) Allow twine tags and args
* (toolchain, bzlmod) Restrict coverage tool visibility under bzlmod
* (pip) Ignore temporary pyc.NNN files in wheels
* (pip) Add format() calls to glob_exclude templates
* plugin_output in py_proto_library rule

### Added

* Using Gazelle's lifecycle manager to manage external processes
* (bzlmod) `pip.parse` can be called multiple times with different Python
  versions
* (bzlmod) Allow bzlmod `pip.parse` to reference the default python toolchain and interpreter
* (bzlmod) Implementing wheel annotations via `whl_mods`
* (gazelle) support multiple requirements files in manifest generation
* (py_wheel) Support for specifying `Description-Content-Type` and `Summary` in METADATA
* (py_wheel) Support for specifying `Project-URL`
* (compile_pip_requirements) Added `generate_hashes` arg (default True) to
  control generating hashes
* (pip) Create all_data_requirements alias
* Expose Python C headers through the toolchain.

[0.24.0]: https://github.com/bazelbuild/rules_python/releases/tag/0.24.0
