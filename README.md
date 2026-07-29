# cdf-crypto

#### 介绍

CDF的全称是Confidential Data defensive Framework，提供敏感数据保护框架SDK库，提供密码算法强度和密钥安全隔离等安全配置模板，提升敏感数据防护安全性，供开发者参考。

#### 软件架构

![](docs/images/cdf_introduction.png)


#### 安装教程

编译运行

1. 编译环境要求

+ 发布目标环境要求：OpenEuler 内核版本不低于 kernel 6.6。
+ Rand/Cryption 使用 OpenSSL 3 Provider/EVP API，支持 OpenSSL 3.0.9
  及以上版本。项目声明和 `--fetch-deps` 基线为 OpenSSL 3.0.9；
  离线构建需要 `external/openssl` 为 OpenSSL 3.0.9 或更高版本 Git
  工作树，也可以通过 `--fetch-deps` 下载 OpenSSL 3.0.9。
+ 当前已验证 OpenSSL 3.0.9、3.1.8、3.3.7、3.5.7 和 4.0.1 下
  Rand/Cryption 构建与测试通过。
+ 内置 BLAKE3 后端默认关闭。使用 `--enable-blake3` 显式启用；离线
  构建需要 `external/blake3`，也可同时使用 `--fetch-deps` 下载
  BLAKE3 1.8.5。
+ 测试环境可按实际发行版安装同名或等价软件包；以下以 yum 系包名为例。

基础编译工具，适用于 `build`、`test`、`coverage`、`install` 和 `package rpm`：

```
sudo yum install -y make
sudo yum install -y cmake
sudo yum install -y gcc
sudo yum install -y gcc-c++
sudo yum install -y perl
sudo yum install -y git
```

系统三方开发包，适用于未使用 `--fetch-deps` 的离线构建：

```
sudo yum install -y libboundscheck
sudo yum install -y rapidjson-devel
sudo yum install -y krb5-devel
sudo yum install -y krb5-libs
sudo yum install -y openssl
sudo yum install -y openssl-devel
```

`--fetch-deps` 会在构建目录中下载并构建项目私有依赖，不会替代基础编译工具。
下载构建 Kerberos 还需要 Autoconf；OpenSSL 和部分依赖构建需要 GNU Make、Perl
和 Git：

```
sudo yum install -y autoconf
```

测试依赖：

```
# test 和 coverage 需要 CTest 3.21 或更高版本，通常随 cmake 提供。
# 离线测试需要 external/gtest；也可以通过 --fetch-deps 下载 GTest。
```

Coverage 依赖：

```
# Coverage 仅支持 GCC。gcov 由 gcc 包提供，版本需要与 GCC 匹配。
# 覆盖率报告由 lcov 和 genhtml 生成；genhtml 通常由 lcov 包提供。
sudo yum install -y lcov
```

RPM 打包和 ASan/Fuzz 插桩依赖：

```
sudo yum install -y rpm-build
sudo yum install -y libasan
```

当前 CMake 构建路径未直接使用 `automake` 和 `bison`；仅在额外工具链或发行版打包
流程需要时安装。

2. 编译指导

+ 默认构建（Release、全部模块、离线依赖）

```
bash build.sh
```

+ 测试、覆盖率、安装和 RPM

```
bash build.sh test --profile debug
bash build.sh test --profile debug --modules rand
bash build.sh coverage
bash build.sh install --fetch-deps
bash build.sh package rpm --fetch-deps
```

`test` 和 `coverage` 要求 CTest 3.21 或更高版本，并在对应构建目录的
`Testing/test_results.xml` 生成 JUnit 测试报告。

Coverage 仅支持 GCC，报告位于 `build/coverage/report/`。当前覆盖率目标为
Lines 70%、Branches 50%，仅用于质量跟踪，不作为持续集成硬门槛。

+ 指定模块和 Debug 配置

```
bash build.sh build --profile debug --modules rand,authorization
```

+ 显式启用 BLAKE3 内置后端并下载依赖

```
bash build.sh build --modules cryption --enable-blake3 --fetch-deps
```

+ `config.sh` 是简化入口，等价于执行 `bash build.sh build`，其后参数会原样传递：

```
bash config.sh --profile debug --modules rand,authorization
```

+ 完整命令、参数、产物位置和旧命令迁移见[构建指南](docs/build.md)

3. 安装指导

+ RPM 构建后进行安装

```
sudo rpm -ivh --nodeps package/rpm/cdf-crypto-*.rpm
# 库目录由 CMake 的 GNUInstallDirs 决定。openEuler 64 位环境通常为
# /usr/lib64/cdf；其他平台也可能为 /usr/lib/cdf，请按实际目录设置。
echo 'export LD_LIBRARY_PATH=/usr/lib64/cdf:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```
#### 相关文档

- [接口文档](docs/api_documentation.md)
- [使用说明](docs/usage_guidelines.md)

#### 许可证信息

本项目遵循 Mulan PSL v2 许可证协议，详情请见 [LICENSE](LICENSE) 文件。

#### 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request


#### 特技

1.  使用 Readme\_XXX.md 来支持不同的语言，例如 Readme\_en.md, Readme\_zh.md
2.  Gitee 官方博客 [blog.gitee.com](https://blog.gitee.com)
3.  你可以 [https://gitee.com/explore](https://gitee.com/explore) 这个地址来了解 Gitee 上的优秀开源项目
4.  [GVP](https://gitee.com/gvp) 全称是 Gitee 最有价值开源项目，是综合评定出的优秀开源项目
5.  Gitee 官方提供的使用手册 [https://gitee.com/help](https://gitee.com/help)
6.  Gitee 封面人物是一档用来展示 Gitee 会员风采的栏目 [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)
