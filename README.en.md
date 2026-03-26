# cdf-crypto

#### Description
The full name of CDF is Confidential Data defensive Framework. It provides an SDK library for sensitive data protection, offering security configuration templates such as cryptographic algorithm strength and key security isolation, thereby enhancing the security of sensitive data protection for developers' reference.

#### Software Architecture
![](./docs/images/cdf_introduction.png)

#### Installation

Build And Install
1. Compilation Environment Requirements

+ OpenEuler Kernel VerSion >= 6.6
+ You also need to install the following dependency packages

```
sudo yum install -y rpm-build
sudo yum install -y make
sudo yum install -y cmake
sudo yum install -y gcc
sudo yum install -y gcc-c++
sudo yum install -y libasan
```
+ Other dependencies are downloaded automatically by default
2. Build Instructions
+ Compile directly with the preconfigured script
```
sh build.sh output
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
# set LD_LIBRARY_PATH
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
