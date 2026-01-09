# cdf-crypto

#### 介绍


#### 软件架构
软件架构说明


#### 安装教程

编译运行
1. 编译环境要求
+ 编译环境要求：kernel 6.6
+ 同时你需要安装以下依赖包

```
yum install -y rpm-build
yum install -y make
yum install -y cmake
yum install -y gcc
yum install -y gcc-c++
yum install -y libboundscheck
yum install -y rapicjson-devel
yum install -y openssl-devel
yum install -y krb5-libs krb5-devel
```
2. 编译指导

+ 直接通过预制脚本编译
```
sh build.sh cicd_default
```
+ rpm包构建
```
sh build.sh rpm
```
+ 编译选项
```
--help         # 显示帮助信息
--debug        # debug模式
--enable       # 支持编译部分模块，用空格分隔模块
```
3. 安装指导
+ rpm包构建后进行安装
```
sudo rpm -ivh --nodes /package/rpm/cdf-crypto-*.rpm
```
#### 功能说明
1. 命令行工具Cli：提供调用密钥管理组件功能的二进制工具。
2. 鉴权模块authentication：提供Kerberos以及JWT token鉴权能力。
3. 授权模块authorization：提供基于白名单的授权能力。
4. 密码学算法模块cryption：提供基于openssl的密码学算法能力，包含hash、hmac、加解密能力。
5. 密钥管理模块key_management：提供基于openbao、vault的密钥管理能力。
6. psk管理模块psk_management：提供psk密钥管理能力。
7. 随机数模块rand：提供安全随机数能力。

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
