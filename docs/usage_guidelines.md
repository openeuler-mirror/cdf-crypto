# 使用指南

## 1. 三方环境配置（可选）

### 1.1 安装配置 Kerberos

#### 1.1.1 安装Kerberos

```shell
yum install krb5-devel krb5-workstation krb5-server 
```

#### 1.1.2 配置/etc/krb5.conf

1. 打开/etc/krb5.conf配置文件。

```
vim /etc/krb5.conf
```

2. 按“i”进入编辑模式，在文件中添加如下内容。

```
[libdefaults]
default_realm = EXAMPLE.COM
kdc_timesync = 1
ccache_type = 4
forwardable = true
proxiable = true
[realms]
EXAMPLE.COM = {
kdc = localhost
admin_server = localhost
}
[domain_realm]
.example.com = EXAMPLE.COM
example.com = EXAMPLE.COM
```

3. 按“Esc”键退出编辑模式，输入:wq!，按“Enter”键退出并保存文件。

#### 1.1.3 创建kerberos数据库

1. 执行以下命令创建kerberos数据库

```
sudo kdb5_util create -r EXAMPLE.COM -s
```

2. 显示以下提示，输入主密码，按Enter键确认。

```
Enter KDC database master key:
```

3. 显示以下提示，再次输入主密码，按Enter键确认。

```
Re-enter KDC database master key to verify:
```

#### 1.1.4 启动krb5kdc、kadmin服务

```
systemctl start kadmin.service krb5kdc.service
```

#### 1.1.5 创建test用户

1. 执行以下命令，进入kadmin.local会话。

```
sudo kadmin.local
```

2. 执行以下命令创建用户身份。

```
addprinc user@EXAMPLE.COM
```

3. 显示以下提示，输入密码，按Enter键确认。

```
No policy specified for user@EXAMPLE.COM; defaulting to no policy
Enter password for principal "user@EXAMPLE.COM":
```

4. 显示以下提示，再次输入密码，按Enter键确认。

```
Re-enter password for principal "user@EXAMPLE.COM":
```

5. 显示以下提示表示创建用户身份成功。

```
Principal "user@EXAMPLE.COM" created.
```

6. 执行以下命令创建服务身份。

```
addprinc server@EXAMPLE.COM
```

7. 显示以下提示，输入密码，按Enter键确认。

```
No policy specified for user@EXAMPLE.COM; defaulting to no policy
Enter password for principal "user@EXAMPLE.COM":
```

8. 显示以下提示，再次输入密码，按Enter键确认。

```
Re-enter password for principal "user@EXAMPLE.COM":
```

9. 显示以下提示表示创建服务身份成功。

```
Principal "server@EXAMPLE.COM" created.
```

#### 1.1.6 创建KeyTable

1. 执行以下命令进入ktuil会话。

```
ktutil
```

2. 执行以下命令。

```
add_entry -password -p user@EXAMPLE.COM -k 1 -e aes256-cts-hmac-sha384-192
```

3. 显示以下提示，输入用户身份密码，按Enter键确认。

```
Password for user@EXAMPLE.COM:
```

4. 执行以下命令。

```
add_entry -password -p server@EXAMPLE.COM -k 1 -e aes256-cts-hmac-sha384-192
```

5. 显示以下提示，输入服务身份密码，按Enter键确认。

```
Password for server@EXAMPLE.COM:
```

6. 执行以下命令创建keytab。

```
wkt example.keytab
```

#### 1.1.7 重启krb5kdc、kadmin服务

```
systemctl restart kadmin.service krb5kdc.service
```

### 1.2 安装配置 OpenBao/Vault

#### 1.2.1 OpenBao

1. 执行以下命令安装 OpenBao

   ```shell
   wget -c https://github.com/openbao/openbao/releases/download/v2.2.1/bao_2.2.1_linux_amd64.rpm
   sudo rpm -i bao_2.2.1_linux_amd64.rpm
   ```

2. 使用 sudo 修改 OpenBao 配置文件 /etc/openbao/openbao.hcl，建议启用https，并按照openbao官方指导进行安全配置，参考：  https://openbao.org/docs/configuration/listener/tcp/#tls-parameters, 以下章节以http作为演示（如果启用https后，以下章节替换为https）

   ```shell
   ui = true
   
   storage "file" {
     path = "/opt/openbao/data"
   }
   
   # HTTP listener
   listener "tcp" {
     address = "127.0.0.1:8200"
     tls_disable = 1
   }
   
   # HTTPS listener
   #listener "tcp" {
   # address       = "0.0.0.0:8200"
   #  tls_cert_file = "/opt/openbao/tls/tls.crt"
   #  tls_key_file  = "/opt/openbao/tls/tls.key"
   #}
   
   # Example AWS KMS auto unseal
   #seal "awskms" {
   #  region = "us-east-1"
   #  kms_key_id = "REPLACE-ME"
   #}
   ```

3. 启动 OpenBao 服务

   ```shell
   sudo systemctl start openbao.service
   ```

4. 全局初始化，注意初始化后会显示出唯一的  unseal key 以及 initial root token，需要谨慎保存

   ```shell
   export BAO_ADDR="http://127.0.0.1:8200" # 如必要
   bao operator init -key-shares=1 -key-threshold=1
   ```

5. 解封 OpenBao

   ```shell
   export BAO_ADDR="http://127.0.0.1:8200" # 如必要
   bao operator unseal
   [输入 unseal key]
   ```

6. 打开 transit engine

   ```shell
   export BAO_ADDR="http://127.0.0.1:8200" # 如必要
   bao login
   [输入 token]
   bao secrets enable transit
   ```

7. （可选）创建临时用户，配置相应权限以及 token

   ```shell
   export BAO_ADDR="http://127.0.0.1:8200" # 如必要
   bao auth enable userpass # 打开临时用户
   
   # 创建新的用户 policy，位于 $HOME/tmp/temp-user-policy.hcl，内容如下（内容可自定义修改）
   # path "transit/*" {
   #  capabilities = ["read", "create", "delete", "scan", "list", "update"]
   # }
   # 应用 policy
   bao policy write temp-user-policy $HOME/tmp/temp-user-policy.hcl
   
   # 创建新用户(xxxx用户自行输入)
   bao write auth/userpass/users/tempuser\
       password=xxxx\
       policies=temp-user-policy
   
   # 创建新用户的 token
   bao token create -policy=temp-user-policy
   ```

#### 1.2.2 Vault

1. 执行以下命安装 Vault。

   ```shell
   sudo yum install -y yum-utils
   sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
   sudo yum -y install vault
   ```

2. 使用 sudo 修改 Vault 配置文件 /etc/vault.hcl，关闭 https 使用 http 协议

   ```shell
   ui = true
   
   storage "file" {
     path = "/opt/vault/data"
   }
   
   # HTTP listener
   listener "tcp" {
     address = "127.0.0.1:8200"
     tls_disable = 1
   }
   
   # HTTPS listener
   #listener "tcp" {
   # address       = "0.0.0.0:8200"
   #  tls_cert_file = "/opt/vault/tls/tls.crt"
   #  tls_key_file  = "/opt/vault/tls/tls.key"
   #}
   
   # Example AWS KMS auto unseal
   #seal "awskms" {
   #  region = "us-east-1"
   #  kms_key_id = "REPLACE-ME"
   #}
   ```

3. 启动 Vault 服务

   ```shell
   sudo systemctl start vault.service
   ```

4. 全局初始化，注意初始化后会显示出唯一的  unseal key 以及 initial root token，需要谨慎保存

   ```shell
   export VAULT_ADDR="http://127.0.0.1:8200" # 如必要
   vault operator init -key-shares=1 -key-threshold=1
   ```

5. 解封 Vault

   ```shell
   export VAULT_ADDR="http://127.0.0.1:8200" # 如必要
   vault operator unseal
   [输入 unseal key]
   ```

6. 打开 transit engine

   ```shell
   export VAULT_ADDR="http://127.0.0.1:8200" # 如必要
   vault login
   [输入 token]
   vault secrets enable transit
   ```

7. （可选）创建临时用户，配置相应权限以及 token

   ```shell
   export VAULT_ADDR="http://127.0.0.1:8200" # 如必要
   vault auth enable userpass # 打开临时用户
   
   # 创建新的用户 policy，位于 $HOME/tmp/temp-user-policy.hcl，内容如下（内容可自定义修改）
   # path "transit/*" {
   #  capabilities = ["read", "create", "delete", "scan", "list", "update"]
   # }
   # 应用 policy
   vault policy write temp-user-policy $HOME/tmp/temp-user-policy.hcl
   
   # 创建新用户(xxxx用户自行输入)
   vault write auth/userpass/users/tempuser\
       password=xxxx\
       policies=temp-user-policy
   
   # 创建新用户的 token
   vault token create -policy=temp-user-policy
   ```

## 2. 开发样例

### 2.1 JWT鉴权

```c++
// 需提前安装密钥管理软件，例如OpenBao，并在OpenBao中生成domainId为0的密钥（可通过命令行或接口生成）
// 样例：通过配置，实现jwt生成token -> 鉴权token流程
int32_t JwtExample(){ 	
    cdf::JWTAuthServer jwtServer;

    // 1.jwt服务器启动配置
    cdf::CDFDistAuthServerOptions options = {};
    options.algType = CryptoHmacAlg::HMAC_SHA256;  	// 安全加密算法
    options.serverKeyExpiredHours = 24;  			// 服务器用于加解密的key过期时间
    options.tokenExpireMinutes = 480;  				// token过期时间
    options.execPath = "";  						// 密钥管理软件可执行文件的路径，例如/usr/bin/bao
    options.accessToken = "";  						// 密钥管理软件token
    options.domainCount = 2;  						// OpenBao密钥管理domain限制
    options.domainId = 0;  							// OpenBao密钥Id

    // 2.启动jwt
    jwtServer.Start(options);

    // 3.设置服务器加密key
    std::string key = "xxxx";			// 用户指定key
    jwtServer.SetEncryptionKey(key);
    
    // 4.获取令牌长度
    std::string input = "userName@xxxx";  // 需要生成token的原始内容，用户自行输入
    auto result = jwtServer->EstimateTokenLength(input.size());
    uint32_t tokenLen = result.second;
    tokenLen += 1;
    
	// 5.创建令牌
    std::vector<char> token(tokenLen);
    CDFDistAuthCreateTokenOptions tokenOptions {};
    tokenOptions.input = input.c_str();
    tokenOptions.inputLen = input.length() + 1;
    tokenOptions.token = token.data();
    tokenOptions.tokenLen = tokenLen;
    auto result1 = jwtServer->CreateToken(tokenOptions);
    
    // 6.配置待校验的token结构体
    cdf::CDFDistAuthValidateTokenOptions validateTokenOptions{};
    validateTokenOptions.token = token.c_str();
    validateTokenOptions.tokenLen = token.length() + 1;
    
    // 7.校验token
    result = jwtServer.ValidateToken(validateTokenOptions);

    // 8.停止jwt
    jwtServer.Stop();
    return 0;
}
```

### 2.2 KerBeros鉴权

```c++
// 需提前安装KerBeros
const std::string serverPrincipalName = "server@EXAMPLE.COM";	// 服务端名称
const std::string clientPrincipalName = "user@EXAMPLE.COM";		// 客户端名称
const std::string keyTabFilePath = "./example.keytab";			// keytab位置
// 样例：基于KerBeros三方库，实现以凭证(Ticket)为基础的客户端、服务端双向认证功能
void KerBerosExample(){
	char *keytable;						// 密钥表
    uint32_t keytableLen = 0;			// 密钥表长度
    bool enableEncryption = false;		// 是否加密keytable
    
    cdf::KrbServer server;

    // 1.从密钥表文件中加载Kerberos认证密钥
    server.GetKerberosKeytab(keyTabFilePath, &keytable, &keytableLen, enableEncryption);
    
    // 2.服务器初始化
    server.ServerInit(serverPrincipalName, {keytable, keytableLen});
	
    // 3.客户端初始化
    cdf::KrbClient client;
    client.ClientInit(clientPrincipalName, serverPrincipalName, {keytable, keytableLen});

    // 4.客户端获取KerBeros票据凭证(Ticket)
    auto [ret, cred] = client.ClientGetCred(0);	// 0为未来扩展参数，当前版本未启用

    // 5.客户端将凭证传递给服务端
    std::string serverInCred;
    serverInCred.resize(cred.size());
    memcpy(serverInCred.data(), cred.data(), cred.size());

    // 6.服务端验证客户端凭证并生成服务端响应凭证
    char *serverCredOut;
    uint32_t serverCredLenOut;
    server.ServerAuth(0, serverInCred, &serverCredOut, &serverCredLenOut);
    
	// 7.客户端验证服务端凭证，完成双向认证
    client.ClientAuthServer(0, serverCredOut, serverCredLenOut);
}
```

### 2.3 授权

```c++
// 样例：通过配置白名单，授予白名单用户权限，并校验
void WhitelistAuthExample(){ 
    auto authorizor = WhitelistAuthorization();

    // 1.添加白名单配置
    rapidjson::Document document;
    document.SetArray();
    
    rapidjson::Value user1(rapidjson::kObjectType);
    user1.AddMember("user", "user1", document.GetAllocator());
    user1.AddMember("allow", rapidjson::kTrueType, document.GetAllocator());
    document.PushBack(user1, document.GetAllocator());
    
    // 2. 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
	rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
	document.Accept(writer);
	std::string conf = buffer.GetString();
    // conf的json格式内容
    // [
  	// 	{
    //		"user": "user1",
    //		"allow": true
  	//	}
	// ]
    
    // 3.初始化白名单
    authorizor.Initialize(conf);
    
    // 4.校验权限
    authorizor.CheckPermission("user1", "xx", "xx"); // 仅校验user1, "xx"为未来扩展参数，当前版本未启用

    // 5.获取所有白名单用户
    std::vector<std::string> principals;
    authorizor.GetAllPrincipals(principals);
} 
```

### 2.4 加解密

```c++
// 样例：实现对明文加解密功能
void EncryptAndDecryptExample(){ 
	NativeCryptor cryptor;
    std::vector<std::byte> plaintext;
    std::vector<std::byte> key;
    
    // 1.提供需要加密的明文
    plaintext.push_back(std::byte{1});
    
    // 2.提供加密密钥
    std::vector<std::byte> key(32, std::byte{0});
	
    // 3.加密
    auto ret = cryptor.Encrypt(cdf::CryptoSymAlg::AES256_GCM, plaintext, key);
	
    // 4.解密
    ret = cryptor.Decrypt(cdf::CryptoSymAlg::AES256_GCM, ret.second, key);

    // 5.对比加解密结果
    for (size_t i = 0; i < ret.second.size(); ++i) {
        if (plaintext[i] != (ret.second)[i]) {
        	// 若加密前后明文不同，加密失败
        }
    }
} 
```

### 2.5 密钥管理

```c++
// 需提前安装密钥管理，例如OpenBao
const std::string KM_EXEPATH = "./";		// openbao可执行文件路径
const std::string KM_ACCESSTOKEN = "";		// openbao token
const std::int DEFAULT_DOMAIN_COUNT = 2;  	// openbao的domain数量限制
// 样例：实现创建、展示、删除密钥管理能力
void KeyManagementExample(){
    // 1.密钥管理单例对象指针获取
    auto *Openbaokm = cdf::KeyManagerFactory::Borrow(KeyManagerTy::OPENBAO);
    
    // 2.openbao 初始化
    Openbaokm->Init(KM_EXEPATH, KM_ACCESSTOKEN, DEFAULT_DOMAIN_COUNT);
    
    // 3.在domainId为0的域下，创建密钥
    std::pair<KeyManagerRC, uint32_t> ret = Openbaokm->CreateKey(0);
    
    // 4.展示所有密钥
    Openbaokm->DisplayAllKey();
    
	// 5.删除domainId为0下，且keyId为ret.second的密钥
    Openbaokm->RemoveKey(0, ret.second);
    
    // 6.去初始化
    Openbaokm->UnInit();
}
```

### 2.6 PSK密钥管理

```c++
// 需提前安装密钥管理，例如OpenBao，并在OpenBao中生成domainId为0的密钥（可通过命令行或接口生成）
const std::string KM_EXEPATH = "./";		
const std::string KM_ACCESSTOKEN = "";		
const std::int DEFAULT_DOMAIN_COUNT = 2;  	
// 样例：实现生成、更新、删除psk密钥管理能力
void PskManagementExample()
{
    // 1.psk密钥管理初始化
    cdf::PsKManagerInitOptions options = {};
    options = {};
    options.algType = cdf::CryptoSymAlg::AES256_GCM;	// 加密算法
    options.exePath = KM_EXEPATH;						// openbao可执行文件路径
    options.accessToken = KM_ACCESSTOKEN;				// openbao token
    options.domainCount = DEFAULT_DOMAIN_COUNT;			// openbao的domain数量限制
    options.domainId = 0;								// openbao密钥管理domainId
    options.pskMaxCount = 1000;							// psk最大数量限制     
    auto &pskMgr = cdf::PskManager::GetInstance();
    pskMgr.Init(options);
    
    // 2.密钥信息配置参数
    cdf::PskParam pskParam = {};
    pskParam.issuer = "Huawei";						// 签发者
    pskParam.subject = "Huawei Subject";			// 使用者
    pskParam.pskLength = 256;						// psk长度
    pskParam.validDays = 30;						// psk有效期
    pskParam.beginTime = std::time(nullptr);		// 开始时间
    
    // 3.注册生成psk回调函数，用于自行决定存储方式，更新psk回调函数同理，按需设置
    cdf::PskCallbackMgr &manager = cdf::PskCallbackMgr::GetInstance();
    manager.RegisterCreatePskCallBack(CreatePskCb);
    
    // 4.生成psk
    cdf::Psk outputPsk;
    pskMgr.GeneratePsk(pskParam, outputPsk);
    
    // 5.更新指定psk
    cdf::Psk updatePsk;
    pskMgr.UpdatePsk(outputPsk.GetPskId(), outputPsk.GetPskContent(), updatePsk);
    
    // 6.删除指定psk
    pskMgr.DeletePsk(outputPsk.GetPskId());
}

cdf::PskManagerRC CreatePskCb(const uint32_t pskId, const std::vector<std::byte> pskCiphertext)
{
    // 自行存储数据
    return cdf::PskManagerRC::OK;
}
```



