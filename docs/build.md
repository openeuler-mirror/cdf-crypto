# 构建指南

## 环境要求

- CMake 3.14.1 或更高版本；
- 支持 C++17 的 GCC 或 Clang；
- Git、GNU Make 和 Perl，用于隔离构建 OpenSSL 源码；下载构建 Kerberos 还需要
  Autoconf；
- 离线构建 Rand/Cryption 需要 `external/openssl` 中的 OpenSSL 3.0.9 Git
  工作树；也可以使用 `--fetch-deps` 允许下载；
- libboundscheck、RapidJSON 和 Kerberos 使用系统开发包，或者通过
  `--fetch-deps` 下载；
- 测试需要 `external/gtest` 源码，或者使用 `--fetch-deps` 下载 GTest；
- Coverage 仅支持 GCC，需要与 GCC 版本匹配的 GNU gcov 和 gcovr；
- RPM 打包需要 CPack 和 rpmbuild。

## 快速开始

默认命令构建 Release 产品目标、全部模块、静态库和共享库。默认不构建测试，也不
访问网络：

```bash
bash build.sh
```

允许自动下载依赖：

```bash
bash build.sh build --fetch-deps
```

运行测试、生成覆盖率报告、安装和打包：

```bash
bash build.sh test --profile debug
bash build.sh test --profile debug --modules rand
bash build.sh coverage
bash build.sh install --fetch-deps
bash build.sh package rpm --fetch-deps
```

## 命令

| 命令 | 功能 |
| --- | --- |
| `build` | 配置并构建产品目标；未指定命令时执行该命令。 |
| `test` | 构建并通过 CTest 运行所有适用测试。 |
| `coverage` | 构建、运行测试并生成覆盖率报告。 |
| `install` | 构建并安装到暂存目录。 |
| `package rpm` | 使用 Release 配置生成 RPM。 |
| `fuzz` | 构建带 ASan 和 Fuzz 插桩的现有目标。 |
| `clean [scope]` | 删除指定的项目生成目录。 |
| `help` | 显示命令和参数帮助。 |

仓库当前没有独立 Fuzz harness。`fuzz` 构建带插桩的 CDF 库和现有可执行目标，不
生成业务 Fuzz 输入。构建会链接弱默认覆盖回调；接入真实 Fuzz 引擎时，其强符号
回调可覆盖这些默认实现。

## 参数及适用范围

| 参数 | 含义 | 默认值 |
| --- | --- | --- |
| `--profile <debug\|release\|asan>` | 选择构建类型和插桩。 | `release` |
| `--modules <a,b,...>` | 构建指定模块及传递依赖。 | 全部模块 |
| `--fetch-deps` | 允许自动下载缺失依赖。 | 禁止下载 |
| `--with-tests` | 构建测试程序但不运行。 | 关闭 |
| `--jobs <n>` | 设置正整数并行任务数。 | CPU 数量 |
| `--prefix <path>` | 设置安装暂存目录。 | `output/cdf` |
| `--no-shared` | 不生成共享库。 | 生成共享库 |

| 参数 | build | test | coverage | install | package rpm | fuzz |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `--profile` | 是 | 是 | 否 | 是 | 否 | 否 |
| `--modules` | 是 | 是 | 是 | 是 | 是 | 是 |
| `--fetch-deps` | 是 | 是 | 是 | 是 | 是 | 是 |
| `--with-tests` | 是 | 否 | 否 | 否 | 否 | 否 |
| `--jobs` | 是 | 是 | 是 | 是 | 是 | 是 |
| `--prefix` | 否 | 否 | 否 | 是 | 否 | 否 |
| `--no-shared` | 是 | 是 | 是 | 是 | 是 | 是 |

不支持的组合会直接失败，不会静默忽略参数。

`config.sh` 仅作为简化入口保留。它执行 `bash build.sh build`，并将收到的参数原样
传递给 `build` 命令。例如：

```bash
bash config.sh --profile debug --modules rand
```

## Profile

| Profile | CMake 类型 | 附加能力 | 构建目录 |
| --- | --- | --- | --- |
| `release` | Release | 优化和安全加固 | `build/release` |
| `debug` | Debug | 调试符号 | `build/debug` |
| `asan` | Debug | AddressSanitizer | `build/asan` |
| Coverage 固定配置 | Debug | gcov 插桩 | `build/coverage` |
| Fuzz 固定配置 | Debug | ASan 和 Fuzz 插桩 | `build/fuzz` |

不同 Profile 使用独立 CMake Cache，不会互相继承 Coverage、ASan 或模块状态。
`coverage` 每次运行会先重建 `build/coverage`，避免源码移动或删除后残留的 gcov
元数据污染报告；其他 Profile 仍采用增量构建。

脚本会向构建、安装、CTest 和 CPack 显式传递当前 CMake 配置，因此单配置和多配置
生成器使用同一个 Profile 语义。每次重新配置后只清理该 Profile 的最终 `bin` 和
`<libdir>` 产物，保留对象文件和第三方依赖缓存，避免关闭共享库、CLI 或测试后留下
可被误认为本次结果的旧文件。

## 模块选择和自动依赖

支持模块：

```text
authentication
authorization
cryption
cli_tool
key_management
rand
psk_management
```

示例：

```bash
bash build.sh build --modules rand,authorization
```

模块解析器会计算传递依赖，并在配置摘要中分别输出请求模块、自动启用模块和最终
模块。例如 `rand` 不自动启用其他业务模块；`cryption` 会自动启用 `rand`。

当前自动依赖：

| 模块 | 直接依赖 |
| --- | --- |
| `rand` | 无 |
| `cryption` | `rand` |
| `key_management` | `cryption` |
| `authentication` | `cryption`、`key_management` |
| `authorization` | 无 |
| `psk_management` | `cryption`、`key_management`、`rand` |
| `cli_tool` | `cryption`、`key_management` |

`package rpm --modules ...` 会保留当前的部分模块打包能力，但部分包与全量包仍使用
相同的 `cdf-crypto` 软件包身份，不能在同一系统中并存。命令执行时会打印警告；正式
发布模块化 RPM 前应另行设计子包或独立包名。

`CcsecCryptErrorCode` 定义在公共头
`cdf/base/crypt_error.h`，因此 rand 公共接口不依赖 cryption 头。`KmCryptor`
属于 key_management，头文件路径为
`cdf/modules/key_management/km_cryptor.h`；旧的
`cdf/modules/cryption/km_cryptor.h` 已删除且不提供兼容转发。

基础、工具和连接器源码始终参与 CDF 库构建。原 `cert` 选项已删除，因为项目没有
对应源码、目标、测试或安装规则。

### 模块隔离验证

以下脚本会让七个模块分别作为入口，在独立干净目录中构建共享库、运行适用 CTest
并验证安装结果：

```bash
bash test/cmake/test_module_matrix.sh
```

开发时也可以只验证一个模块：

```bash
bash test/cmake/test_module_matrix.sh rand
bash test/cmake/test_module_matrix.sh key_management
```

临时构建目录默认在 `/tmp` 中创建并自动清理。设置
`CDF_MODULE_MATRIX_ROOT=<path>` 可以保留指定目录，便于排查失败。

`bash build.sh test` 会通过 CTest 同时运行轻量构建契约测试。Coverage、RPM
和完整模块矩阵属于重型集成验证，需要单独执行：

```bash
bash test/cmake/test_coverage_report.sh
bash test/cmake/test_rpm_package.sh
bash test/cmake/test_module_matrix.sh
```

这些脚本使用 `/tmp` 下的隔离工程，不会清理当前工作区的构建和覆盖率产物。
RPM 测试需要 `cpack`、`rpmbuild` 和 `rpm`。

单元测试按模块拆分为以下 CTest 目标：

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

`deploy_verify_rand` 是 Rand 集成测试。开发时可只运行指定目标，例如：

```bash
ctest --test-dir build/debug -R '^cdf_ut_cli$' --output-on-failure
```

## 第三方依赖

默认使用 `external/` 中预先准备的依赖或系统依赖，不访问网络：

```bash
bash build.sh build
```

离线测试使用 `external/gtest`，Rand/Cryption 使用 `external/openssl`。其中
OpenSSL 源码需要保留为 Git 工作树。构建会从其 `HEAD` 导出干净快照到
`build/<profile>/deps/src/` 后进行 out-of-source 编译，不会在
`external/openssl` 中生成或复用构建残留，因此不同 Profile 可以并行构建。

显式允许下载：

```bash
bash build.sh build --fetch-deps
```

下载和编译结果位于对应 Profile 的 `build/<profile>/deps/`。第三方项目不继承
CDF 的 `-Werror`、Coverage、ASan 或安全加固参数。

## 产物位置

| 操作 | 位置 |
| --- | --- |
| Release 构建 | `build/release/bin`、`build/release/<libdir>` |
| Debug 构建 | `build/debug/bin`、`build/debug/<libdir>` |
| ASan 构建 | `build/asan/bin`、`build/asan/<libdir>` |
| Coverage 构建 | `build/coverage/bin`、`build/coverage/<libdir>` |
| Coverage HTML | `build/coverage/report/total.html` |
| Coverage XML | `build/coverage/report/coverage.xml` |
| Coverage 文本 | `build/coverage/report/coverage.txt` |
| Fuzz 构建 | `build/fuzz/bin`、`build/fuzz/<libdir>` |
| 默认安装暂存 | `output/cdf` |
| RPM | `package/rpm/*.rpm` |

`<libdir>` 由 CMake 的 GNUInstallDirs，即 `CMAKE_INSTALL_LIBDIR` 决定，常见值为
`lib` 或 `lib64`。安装暂存中的库相应位于 `output/cdf/<libdir>`；RPM 安装后的
库位于 `/usr/<libdir>/cdf`，应以实际配置结果为准。

生成 RPM 后可从仓库根目录安装：

```bash
sudo rpm -ivh --nodeps package/rpm/cdf-crypto-*.rpm
```

Coverage 仅支持 GCC 编译器生成的覆盖率数据，不支持 Clang/llvm-cov，统计范围为
完整的 `src/cdf/**`。Lines 70%、Branches 50% 是当前质量目标，不通过
`--fail-under-line` 或 `--fail-under-branch` 设置为持续集成硬门槛。覆盖率报告颜色阈值：

- Lines：90% 以上绿色，70% 以上黄色，70% 以下红色；
- Branches：60% 以上绿色，50% 以上黄色，50% 以下红色。

## 清理

```bash
bash build.sh clean
bash build.sh clean build
bash build.sh clean output
bash build.sh clean package
bash build.sh clean all
```

`clean` 默认等同 `clean build`。`clean all` 仅删除 `build/`、`output/` 和
`package/`，不会删除 `external/`。

## 直接使用 CMake

模块列表：

```bash
cmake -S . -B build/custom \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_MODULES="rand;authorization" \
  -DENABLE_DOWNLOAD_DEPENDENCY=OFF
cmake --build build/custom --parallel 8
```

独立模块开关：

```bash
cmake -S . -B build/custom \
  -DENABLE_MODULE_RAND=ON \
  -DENABLE_MODULE_AUTHORIZATION=ON
```

`ENABLE_MODULES` 与各 `ENABLE_MODULE_*` 取并集；没有任何模块选择时默认启用全部
模块。`DOWNLOAD_DEPENDENCY` 仅作为废弃兼容项保留，新配置应使用
`ENABLE_DOWNLOAD_DEPENDENCY`。

## 旧命令迁移

旧命令不会作为别名继续执行：

| 旧行为 | 新命令 |
| --- | --- |
| 旧 `bash build.sh` 或 `bash build.sh all` | `bash build.sh build --with-tests --fetch-deps` |
| 旧 `bash build.sh test` | `bash build.sh test` |
| 旧 `bash build.sh output` | `bash build.sh install --fetch-deps` |
| 旧 `bash build.sh cicd_default` | `bash build.sh install` |
| 旧 `bash build.sh cicd_coverage` | `bash build.sh coverage` |
| 旧 `bash build.sh rpm` | `bash build.sh package rpm --fetch-deps` |
| 旧 `bash build.sh fuzz` | `bash build.sh fuzz` |
| 旧 `-c` 后接构建模式 | 先执行 `bash build.sh clean build`，再执行新命令 |

新版无参数命令只构建产品目标，不再默认构建测试或下载依赖。

## 常见错误

- `Unknown command`：使用了旧命令或拼写错误，运行 `bash build.sh help`；
- `Unknown module`：模块不在支持列表中；
- 依赖源码不存在：准备 `external/`，或者增加 `--fetch-deps`；
- Coverage 工具缺失：使用 GCC，并安装与 GCC 版本匹配的 GNU gcov 和 gcovr；
- 参数不适用于命令：根据“参数及适用范围”调整命令。
