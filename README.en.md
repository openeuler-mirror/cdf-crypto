# cdf-crypto

#### Description
A lib that provides cryptographic algorithms and key security functions.

#### Software Architecture
Software architecture description

#### Installation

Build And Install
1. Compilation Environment Requirements

+ Kernel VerSion >= 6.6
+ You also need to install the following dependency packages

```
yum install -y rpm-build
yum install -y make
yum install -y cmake
yum install -y gcc
yum install -y gcc-c++
```
+ Automatic dependency download is enabled by default. To download dependencies manually, set `enable_download_dependency` in the build.sh file to 'Off'.
+ Manual Dependency Download
```
mkdir -p external
# rapidjson
git clone https://szv-open.codehub.huawei.com/OpenSourceCenter/Tencent/rapidjson.git rapidjson -b 6089180ecb704cb2b136777798fa1be303618975 --depth=1
# libboundscheck
git clone https://szv-open.codehub.huawei.com/OpenSourceCenter/openEuler/libboundscheck.git libboundscheck -b master --depth=1
# krb5
git clone https://szv-open.codehub.huawei.com/OpenSourceCenter/krb5/krb5.git krb5 -b 1.21.3-htrunk2 --depth=1
# openssl
git clone https://szv-open.codehub.huawei.com/OpenSourceCenter/openssl/openssl.git openssl -b 3.0.9-h16 --depth=1
```
2. Build Instructions
+ Compile directly with the preconfigured script
```
sh build.sh cicd_default
```
+ RPM package building
```
sh build.sh rpm
```
+ Compilation options

```
--help         # Display help information
--debug        # Debug mode
--enable       # Support compiling partial modules, separate modules with spaces
```
3. Installation Instructions
+ Install after RPM package building
```
sudo rpm -ivh --nodes /package/rpm/cdf-crypto-*.rpm
```
#### Function Description
+ Cli: Provides a binary tool for calling the functions of the key management component.
+ Authentication: Provides Kerberos and JWT token authentication capabilities.
+ Authorization: Provides whitelist-based authorization capabilities.
+ Cryption: Provides OpenSSL-based cryptography algorithm capabilities, including hash, HMAC, encryption and decryption capabilities.
+ key_management:Provides Openbao and Vault-based key management capabilities.
+ psk_management: Provides PSK key management capabilities.
+ rand: Provides secure random number generation capabilities.

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
