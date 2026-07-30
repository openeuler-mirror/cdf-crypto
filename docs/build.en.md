# Build Guide

## Requirements

- CMake 3.14.1 or newer;
- the `test` and `coverage` commands require CTest 3.21 or newer;
- GCC or Clang with C++17 support;
- Git, GNU Make, and Perl for isolated OpenSSL source builds; downloaded
  Kerberos builds additionally require Autoconf;
- the OpenSSL 3.0.9 Git worktree under `external/openssl` for offline Rand or
  Cryption builds, or `--fetch-deps` to permit downloading it;
- system development packages for libboundscheck, RapidJSON, and Kerberos, or
  `--fetch-deps` to download them;
- the GTest sources under `external/gtest` for offline tests, or
  `--fetch-deps` to download GTest;
- the optional built-in BLAKE3 backend is disabled by default. When
  `--enable-blake3` is used, offline builds require `external/blake3`, or use
  `--fetch-deps` to download BLAKE3 1.8.5;
- Coverage supports GCC only and requires GNU gcov matching the GCC version,
  plus lcov and genhtml from the lcov package;
- CPack and rpmbuild for RPM packaging.

## Quick Start

The default command builds Release product targets, all modules, and both static
and shared libraries. It does not build tests or access the network:

```bash
bash build.sh
```

Allow dependency downloads explicitly:

```bash
bash build.sh build --fetch-deps
```

Enable the built-in BLAKE3 backend and permit downloading its source:

```bash
bash build.sh build --modules cryption --enable-blake3 --fetch-deps
```

Common actions:

```bash
bash build.sh test --profile debug
bash build.sh test --profile debug --modules rand
bash build.sh coverage
bash build.sh install --fetch-deps
bash build.sh package rpm --fetch-deps
```

`build.sh package rpm` retains the CPack packaging path. To create an SRPM
with pinned OpenSSL and BLAKE3 source archives plus debuginfo/debugsource,
run:

```bash
bash scripts/rpm/buildrpm.sh
```

The script downloads and verifies the third-party source archives, then runs
`rpmbuild -ba`. Binary RPMs and the SRPM are written to `package/rpm/` and
`package/srpm/` respectively.

## Commands

| Command | Behavior |
| --- | --- |
| `build` | Configure and build product targets; this is the default command. |
| `test` | Build and run every applicable CTest test. |
| `coverage` | Build, test, and generate coverage reports. |
| `install` | Build and install into a staging prefix. |
| `package rpm` | Create an RPM with the Release configuration. |
| `fuzz` | Build existing targets with ASan and fuzz instrumentation. |
| `clean [scope]` | Remove selected generated project directories. |
| `help` | Show command and option help. |

The repository currently has no standalone fuzz harness. The `fuzz` command
instruments the CDF libraries and existing executables; it does not create
application-specific fuzz inputs. The build links weak default coverage
callbacks, which a real fuzzing engine can replace with strong definitions.

## Options and Applicability

| Option | Meaning | Default |
| --- | --- | --- |
| `--profile <debug\|release\|asan>` | Select build type and instrumentation. | `release` |
| `--modules <a,b,...>` | Build selected modules and transitive dependencies. | all modules |
| `--fetch-deps` | Permit automatic dependency downloads. | disabled |
| `--enable-blake3` | Enable the optional built-in BLAKE3 backend. | disabled |
| `--with-tests` | Build test binaries without running them. | disabled |
| `--jobs <n>` | Set a positive parallel job count. | CPU count |
| `--prefix <path>` | Set the install staging prefix. | `output/cdf` |
| `--no-shared` | Do not build the shared library. | shared enabled |

| Option | build | test | coverage | install | package rpm | fuzz |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `--profile` | yes | yes | no | yes | no | no |
| `--modules` | yes | yes | yes | yes | yes | yes |
| `--fetch-deps` | yes | yes | yes | yes | yes | yes |
| `--enable-blake3` | yes | yes | yes | yes | yes | yes |
| `--with-tests` | yes | no | no | no | no | no |
| `--jobs` | yes | yes | yes | yes | yes | yes |
| `--prefix` | no | no | no | yes | no | no |
| `--no-shared` | yes | yes | yes | yes | yes | yes |

Unsupported combinations fail instead of being silently ignored.

`config.sh` is retained only as a convenience entry point. It invokes
`bash build.sh build` and forwards its arguments unchanged to the `build`
command. For example:

```bash
bash config.sh --profile debug --modules rand
```

## Profiles

| Profile | CMake type | Additional behavior | Build directory |
| --- | --- | --- | --- |
| `release` | Release | optimization and hardening | `build/release` |
| `debug` | Debug | debug symbols | `build/debug` |
| `asan` | Debug | AddressSanitizer | `build/asan` |
| fixed Coverage profile | Debug | gcov instrumentation | `build/coverage` |
| fixed Fuzz profile | Debug | ASan and fuzz instrumentation | `build/fuzz` |

Profiles use separate CMake caches, so Coverage, ASan, and module state cannot
leak between configurations.
Each `coverage` run recreates `build/coverage` so gcov metadata left by moved or
deleted sources cannot contaminate the report. Other profiles remain incremental.

The script passes the selected CMake configuration explicitly to build,
install, CTest, and CPack, so single-config and multi-config generators use the
same profile semantics. After each configure it removes only the profile's
final `bin` and `<libdir>` products while retaining object files and dependency
caches, preventing disabled shared-library, CLI, or test targets from leaving
misleading artifacts.

## Modules and Automatic Dependencies

Supported modules:

```text
authentication
authorization
cryption
cli_tool
key_management
rand
psk_management
```

Example:

```bash
bash build.sh build --modules rand,authorization
```

The resolver prints requested, automatically enabled, and effective modules.
For example, `rand` does not enable another product module, while `cryption`
automatically enables `rand`.

Dependency rules:

| Module | Direct dependencies |
| --- | --- |
| `rand` | none |
| `cryption` | `rand` |
| `key_management` | `cryption` |
| `authentication` | `cryption`, `key_management` |
| `authorization` | none |
| `psk_management` | `cryption`, `key_management`, `rand` |
| `cli_tool` | `cryption`, `key_management` |

`package rpm --modules ...` retains partial-module packaging, but partial and
full packages still use the same `cdf-crypto` package identity and cannot safely
coexist on one system. The command prints a warning. Define subpackages or
distinct package names before publishing modular RPMs.

`CcsecCryptErrorCode` is declared by the common
`cdf/base/crypt_error.h` header, so the public rand API does not depend on a
cryption header. `KmCryptor` belongs to key management and is available from
`cdf/modules/key_management/km_cryptor.h`. The old
`cdf/modules/cryption/km_cryptor.h` path was removed without a forwarding
compatibility header.

Base, utility, and connector sources are always part of the CDF library. The old
`cert` selector was removed because it had no source, target, test, or install
rule.

### Isolated Module Verification

Run every module as an independent entrypoint in a clean build directory. The
script builds the shared library, runs applicable CTest tests, and verifies the
installation for each module:

```bash
bash test/cmake/test_module_matrix.sh
```

To verify one module during development:

```bash
bash test/cmake/test_module_matrix.sh rand
bash test/cmake/test_module_matrix.sh key_management
```

Temporary build directories are created under `/tmp` and removed automatically.
Set `CDF_MODULE_MATRIX_ROOT=<path>` to preserve a chosen directory for failure
investigation.

`bash build.sh test` also runs lightweight build-contract checks through CTest.
Coverage, RPM, and the complete module matrix are heavier integration checks and
run separately:

```bash
bash test/cmake/test_coverage_report.sh
bash test/cmake/test_rpm_package.sh
bash test/cmake/test_module_matrix.sh
```

These scripts use isolated projects below `/tmp` and do not clean the current
workspace's build or coverage artifacts. The RPM test requires `cpack`,
`rpmbuild`, and `rpm`.

Unit tests are split into these module-level executable targets. Each
GoogleTest case is registered with CTest as
`<target>.<test-suite>.<test-case>`:

```text
cdf_ut_base_utils
cdf_ut_cryption
cdf_ut_key_management
cdf_ut_authorization
cdf_ut_authentication_jwt
cdf_ut_authentication_kerberos
cdf_ut_rand
cdf_ut_psk_management
cdf_ut_cli
```

`deploy_verify_rand` is the Rand integration test. During development, run all
GoogleTest cases from one target by name prefix:

```bash
ctest --test-dir build/debug -R '^cdf_ut_cli\.' --output-on-failure
```

The executable target label provides an equivalent selection:

```bash
ctest --test-dir build/debug -L '^cdf_ut_cli$' --output-on-failure
```

## Third-party Dependencies

By default, builds use pre-provisioned sources under `external/` or system
dependencies and do not access the network. Add `--fetch-deps` to permit
downloads. Downloaded dependency builds are stored under
`build/<profile>/deps/`.

Offline tests use `external/gtest`, while Rand and Cryption use
`external/openssl`. Builds with `--enable-blake3` additionally require
`external/blake3`. The offline OpenSSL source must remain a Git worktree. Each
profile exports a clean snapshot from its `HEAD` into
`build/<profile>/deps/src/` and builds it out of source. Builds therefore do
not create or reuse artifacts in `external/openssl`, and different profiles
can run concurrently.

Third-party projects do not inherit CDF `-Werror`, Coverage, ASan, or hardening
flags, and their headers are treated as system includes.

`--fetch-deps` does not enable BLAKE3 by itself. Pass `--enable-blake3`
explicitly when the built-in backend is required.

## Artifact Locations

| Action | Location |
| --- | --- |
| Release | `build/release/bin`, `build/release/<libdir>` |
| Debug | `build/debug/bin`, `build/debug/<libdir>` |
| ASan | `build/asan/bin`, `build/asan/<libdir>` |
| Test JUnit XML | `build/<profile>/Testing/test_results.xml` |
| Coverage build | `build/coverage/bin`, `build/coverage/<libdir>` |
| Coverage test JUnit XML | `build/coverage/Testing/test_results.xml` |
| Coverage HTML | `build/coverage/report/index.html` |
| Coverage lcov data | `build/coverage/report/coverage.info` |
| Fuzz | `build/fuzz/bin`, `build/fuzz/<libdir>` |
| Default install staging | `output/cdf` |
| RPM | `package/rpm/*.rpm` |

`Testing/test_results.xml` is the machine-readable test result for CI,
`Testing/Temporary/LastTest.log` is the raw CTest log, and
`report/coverage.info` contains lcov coverage data. They are not
interchangeable.

GNUInstallDirs determines `<libdir>` through `CMAKE_INSTALL_LIBDIR`; common
values are `lib` and `lib64`. Libraries in the install staging tree therefore
reside in `output/cdf/<libdir>`, and RPM-installed libraries reside in
`/usr/<libdir>/cdf`. Use the directory selected by the actual configuration.

After generating the RPM, install it from the repository root with:

```bash
sudo rpm -ivh --nodeps package/rpm/cdf-crypto-*.rpm
```

Coverage supports GCC-generated coverage data only; Clang/llvm-cov is not
supported. It covers the complete `src/cdf/**` tree. Lines 70% and Branches
50% are quality targets; they are not currently enforced as CI failure
thresholds through `lcov --fail-under-lines` or `genhtml --criteria-script`.
Coverage colors use line thresholds 90/70 and branch thresholds 60/50.
The genhtml top-level Legend shows only the global 90/70 color thresholds;
branch coverage is still colored with the branch-specific 60/50 thresholds.
The build prefers the newer lcov/genhtml `--branch-coverage` option and falls
back to the lcov 1.x-compatible `--rc lcov_branch_coverage=1` and
`--rc genhtml_branch_coverage=1` form when the installed tools do not support
that option.

## Cleaning

```bash
bash build.sh clean
bash build.sh clean build
bash build.sh clean output
bash build.sh clean package
bash build.sh clean all
```

`clean` defaults to `clean build`. `clean all` only removes `build/`, `output/`,
and `package/`; it never removes `external/`.

## Direct CMake Usage

List form:

```bash
cmake -S . -B build/custom \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_MODULES="rand;authorization" \
  -DENABLE_DOWNLOAD_DEPENDENCY=OFF
cmake --build build/custom --parallel 8
```

Individual options:

```bash
cmake -S . -B build/custom \
  -DENABLE_MODULE_RAND=ON \
  -DENABLE_MODULE_AUTHORIZATION=ON
```

`ENABLE_MODULES` and `ENABLE_MODULE_*` form a union. With no module selector,
all modules are enabled. `DOWNLOAD_DEPENDENCY` remains only as a deprecated
alias; new configurations must use `ENABLE_DOWNLOAD_DEPENDENCY`.

## Migration from Old Commands

Old commands are documented here but are not executable aliases:

| Old behavior | New command |
| --- | --- |
| old `bash build.sh` or `bash build.sh all` | `bash build.sh build --with-tests --fetch-deps` |
| old `bash build.sh test` | `bash build.sh test` |
| old `bash build.sh output` | `bash build.sh install --fetch-deps` |
| old `bash build.sh cicd_default` | `bash build.sh install` |
| old `bash build.sh cicd_coverage` | `bash build.sh coverage` |
| old `bash build.sh rpm` | `bash build.sh package rpm --fetch-deps` |
| old `bash build.sh fuzz` | `bash build.sh fuzz` |
| old `-c` followed by a mode | run `bash build.sh clean build`, then the new command |

The new no-argument command builds product targets only; it no longer builds
tests or downloads dependencies by default.

## Common Errors

- `Unknown command`: an old command or typo was used; run `bash build.sh help`;
- `Unknown module`: the name is not in the supported module list;
- missing dependency source: prepare `external/` or add `--fetch-deps`; BLAKE3
  builds require `external/blake3` or `--fetch-deps`;
- missing Coverage tool: use GCC and install GNU gcov matching the GCC version,
  plus lcov and genhtml from the lcov package;
- unsupported option: consult the applicability table above.
