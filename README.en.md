# cdf-crypto

#### Description
The full name of CDF is Confidential Data defensive Framework. It provides an SDK library for sensitive data protection, offering security configuration templates such as cryptographic algorithm strength and key security isolation, thereby enhancing the security of sensitive data protection for developers' reference.

#### Software Architecture
![](./docs/images/cdf_introduction.png)

#### Installation

Build And Install
1. Compilation Environment Requirements

+ OpenEuler Kernel VerSion >= 6.6
+ Openssl version: 3.0.9
+ You also need to install the following dependency packages

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
+ Use `--fetch-deps` to explicitly permit automatic dependency downloads
2. Build Instructions
+ Default build (Release, all modules, offline dependencies)
```
bash build.sh
```
+ Tests, coverage, installation, and RPM packaging
```
bash build.sh test --profile debug
bash build.sh test --profile debug --modules rand
bash build.sh coverage
bash build.sh install --fetch-deps
bash build.sh package rpm --fetch-deps
```
Coverage supports GCC only. Reports are generated under
`build/coverage/report/`. The current Lines 70% and Branches 50% targets are
used for quality tracking and are not enforced as CI failure thresholds.
+ Select modules and the Debug profile

```
bash build.sh build --profile debug --modules rand,authorization
```
+ `config.sh` is a convenience entry point. It delegates to
  `bash build.sh build` and forwards all following options unchanged:

```
bash config.sh --profile debug --modules rand,authorization
```

+ See the [complete build guide](docs/build.en.md) for commands, options,
  artifact locations, and migration from old commands.
3. Installation Instructions
+ Install after RPM package building
```
sudo rpm -ivh --nodeps package/rpm/cdf-crypto-*.rpm
# GNUInstallDirs determines the library directory. It is usually
# /usr/lib64/cdf on 64-bit openEuler, but may be /usr/lib/cdf elsewhere.
echo 'export LD_LIBRARY_PATH=/usr/lib64/cdf:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```
#### Documents

- [api documentation](docs/api_documentation.md)
- [usage guidelines](docs/usage_guidelines.md)

#### License

Confidential Data defensive Framework is licensed under Mulan PSL v2，see [LICENSE](LICENSE) for details。

#### Contribution

1.  Fork the repository
2.  Create Feat_xxx branch
3.  Commit your code
4.  Create Pull Request


#### Gitee Feature

1.  You can use Readme\_XXX.md to support different languages, such as Readme\_en.md, Readme\_zh.md
2.  Gitee blog [blog.gitee.com](https://blog.gitee.com)
3.  Explore open source project [https://gitee.com/explore](https://gitee.com/explore)
4.  The most valuable open source project [GVP](https://gitee.com/gvp)
5.  The manual of Gitee [https://gitee.com/help](https://gitee.com/help)
6.  The most popular members  [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)
