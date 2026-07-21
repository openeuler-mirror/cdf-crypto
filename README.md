# cdf-crypto

#### 介绍

CDF的全称是Confidential Data defensive Framework，提供敏感数据保护框架SDK库，提供密码算法强度和密钥安全隔离等安全配置模板，提升敏感数据防护安全性，供开发者参考。

#### 软件架构

![](docs/images/cdf_introduction.png)


#### 安装教程

编译运行

1. 编译环境要求

+ 编译环境要求：OpenEuler 内核版本不低于 kernel 6.6
+ 编译环境要求：Openssl 3.0.9

```
sudo yum install -y rpm-build
sudo yum install -y make
sudo yum install -y cmake
sudo yum install -y gcc
sudo yum install -y gcc-c++
sudo yum install -y autoconf
sudo yum install -y automake
sudo yum install -y bison
sudo yum install -y perl
sudo yum install -y libboundscheck
sudo yum install -y rapidjson-devel
sudo yum install -y openssl
sudo yum install -y openssl-devel
sudo yum install -y krb5-devel
sudo yum install -y krb5-libs
sudo yum install -y libasan
```

+ 其他依赖可通过 `--fetch-deps` 显式允许自动下载

2. 编译指导

+ 默认构建（Release、全部模块、离线依赖）

```
bash build.sh
```

+ 测试、覆盖率、安装和 RPM

```
bash build.sh test
bash build.sh coverage
bash build.sh install --fetch-deps
bash build.sh package rpm --fetch-deps
```

+ 指定模块和 Debug 配置

```
bash build.sh build --profile debug --modules rand,authorization
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
