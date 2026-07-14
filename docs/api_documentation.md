# 1 数据结构

## 1.1 CDF

### 1.1.1 枚举

#### 1.1.1.1 CryptoSymAlg

**定义**

```c++
enum class CryptoSymAlg : int 
   AES128_GCM = 0, 
   AES256_GCM = 1, 
   SM4_CTR = 2, 
   AES128_CCM = 3, 
   CHACHA20_POLY1305 = 4, 
   UNKNOWN 
 };
```

**用途**

对称加密算法。

**属性说明**

| **名称**          | **值** | **含义**                |
| ----------------- | ------ | ----------------------- |
| AES128_GCM        | 0      | AES128_GCM算法。        |
| AES256_GCM        | 1      | AES256_GCM算法。        |
| SM4_CTR           | 2      | SM4_CTR算法。           |
| AES128_CCM        | 3      | AES128_CCM算法。        |
| CHACHA20_POLY1305 | 4      | CHACHA20_POLY1305算法。 |
| UNKNOWN           | 5      | 未知。                  |

 

#### 1.1.1.2 CryptionRC

**定义**

```c++
enum class CryptionRC : int { 
   OK = 0, 
   ERROR = 1, 
   INVALID_PARAM = 2, 
   KEY_EXPIRED = 3, 
   UNINITED = 4, 
   INIT_FAILED = 5, 
   DOMAIN_COUNT_INVALID, 
   KEY_ACTIVE_FAILED, 
 };
```

**用途**

函数返回错误码。

**属性说明**

| **名称**             | **值** | **含义**           |
| -------------------- | ------ | ------------------ |
| OK                   | 0      | 成功。             |
| ERROR                | 1      | 失败。             |
| INVALID_PARAM        | 2      | 参数异常。         |
| KEY_EXPIRED          | 3      | 密钥过期。         |
| UNINITED             | 4      | 未初始化。         |
| INIT_FAILED          | 5      | 初始化失败。       |
| DOMAIN_COUNT_INVALID | 6      | domain count错误。 |
| KEY_ACTIVE_FAILED    | 7      | 激活密钥失败。     |

 

#### 1.1.1.3 CryptoHmacAlg

**定义**

```c++
enum class CryptoHmacAlg : int { 
   HMAC_SHA256 = 0, 
   HMAC_SHA384 = 1, 
   HMAC_SHA512 = 2, 
   UNKNOWN 
 };
```

**用途**

加密hmac算法类型。

**属性说明**

| **属性名**  | **值** | **描述**     |
| ----------- | ------ | ------------ |
| HMAC_SHA256 | 0      | Sha256算法。 |
| HMAC_SHA384 | 1      | Sha384算法。 |
| HMAC_SHA512 | 2      | Sha512算法。 |
| UNKNOWN     | 3      | 未知。       |

 

#### 1.1.1.4 AuthRC

**定义**

```c++
enum class AuthRC : int { 
   OK = 0, 
   FAILED = 100, 
   CONF_CONFLICT = 101, 
   CONF_INVALID = 102, 
   PARAM_ERROR = 103, 
   CONF_FORMAT_INVALID = 104, 
   NO_SUCH_USER = 105, 
   USER_EXIST = 106, 
   EMPTY_USERNAME = 107, 
   NO_SUCH_ROLE = 108, 
   EMPTY_ROLE = 109, 
   ROLE_EXISTED = 110, 
   NO_SUCH_PERMISSION = 111, 
   ROLE_IN_USE = 112, 
   PERMISSION_IN_USE = 113, 
   PERMISSION_EXISTED = 114, 
   PERMISSION_BIND_FAILED = 115, 
   MALLOC_FAILED = 116, 
   NOT_SUPPORTED_TYPE = 117, 
   SET_EXTERNAL_LOGGER_FAILED = 118 
 };
```

**用途**

授权接口错误码。

**属性说明**

| **名称**                   | **值** | **含义**           |
| -------------------------- | ------ | ------------------ |
| OK                         | 0      | 成功               |
| FAILED                     | 100    | 授权失败           |
| CONF_CONFLICT              | 101    | 配置冲突           |
| CONF_INVALID               | 102    | 配置无效           |
| PARAM_ERROR                | 103    | 参数错误           |
| CONF_FORMAT_INVALID        | 104    | 配置文件格式错误   |
| NO_SUCH_USER               | 105    | 用户不存在         |
| USER_EXIST                 | 106    | 用户已存在         |
| EMPTY_USERNAME             | 107    | 用户名为空         |
| NO_SUCH_ROLE               | 108    | 无此角色           |
| EMPTY_ROLE                 | 109    | 角色名为空         |
| ROLE_EXISTED               | 110    | 角色已存在         |
| NO_SUCH_PERMISSION         | 111    | 权限不存在         |
| ROLE_IN_USE                | 112    | 角色仍在使用       |
| PERMISSION_IN_USE          | 113    | 权限仍在使用       |
| PERMISSION_EXISTED         | 114    | 权限已存在         |
| PERMISSION_BIND_FAILED     | 115    | 角色与权限绑定失败 |
| MALLOC_FAILED              | 116    | 内存分配失败       |
| NOT_SUPPORTED_TYPE         | 117    | 授权类型不支持     |
| SET_EXTERNAL_LOGGER_FAILED | 118    | 设置外部日志失败   |

 

#### 1.1.1.5 JwtAuthRC

**定义**

```c++
enum class JwtAuthRC : int { 
   OK = 0, 
   ERROR = 200, 
   NEW_OBJ_FAIL = 201, 
   NOT_SUPPORTED = 202, 
   PARAM_INVALID = 203, 
   BASE64_ENCODE_FAIL = 204, 
   BASE64_DECODE_FAIL = 205, 
   HMAC_ENCODE_FAIL = 206, 
   OPENSSL_INIT_FAIL = 207, 
   TOKEN_EXPIRED = 208, 
   CREATE_TOKEN_FAIL = 209, 
   TOKEN_VALIDATE_FAIL = 210, 
   KEY_PASS_INVALID = 211, 
   KMC_INIT_FAIL = 212, 
   KMC_ENCODE_FAIL = 213, 
   KMC_DECODE_FAIL = 214, 
   ERASE_KEY_FAIL = 215, 
   REFRESH_KEY_FAIL = 216, 
   SET_KEY_FAIL = 217, 
   UNKNOWN, 
 };
```

**用途**

JWT Token鉴权错误码。

**属性说明**

| **名称**            | **值** | **含义**          |
| ------------------- | ------ | ----------------- |
| OK                  | 0      | 成功              |
| ERROR               | 200    | 失败              |
| NEW_OBJ_FAIL        | 201    | 创建对象失败      |
| NOT_SUPPORTED       | 202    | 不支持的类型      |
| PARAM_INVALID       | 203    | 参数错误          |
| BASE64_ENCODE_FAIL  | 204    | Base64编码失败    |
| BASE64_DECODE_FAIL  | 205    | Base64解码失败    |
| HMAC_ENCODE_FAIL    | 206    | Hmac编码失败      |
| OPENSSL_INIT_FAIL   | 207    | OpenSSL初始化失败 |
| TOKEN_EXPIRED       | 208    | Token过期         |
| CREATE_TOKEN_FAIL   | 209    | 创建Token失败     |
| TOKEN_VALIDATE_FAIL | 210    | Token校验失败     |
| KEY_PASS_INVALID    | 211    | 密钥无效          |
| KMC_INIT_FAIL       | 212    | Kmc初始化失败     |
| KMC_ENCODE_FAIL     | 213    | Kmc编码失败       |
| KMC_DECODE_FAIL     | 214    | Kmc解码失败       |
| ERASE_KEY_FAIL      | 215    | 清除密钥失败      |
| REFRESH_KEY_FAIL    | 216    | 刷新密钥失败      |
| SET_KEY_FAIL        | 217    | 设置密钥失败      |
| UNKNOWN             | 218    | 未知错误          |

 

#### 1.1.1.6 JwtAuthMode

**定义**

```c++
enum class JwtAuthMode : int { 
   INTERNAL_KEY = 0, 
   EXTERNAL_KEY = 1, 
   UNKNOWN, 
 };
```

**用途**

分布式鉴权服务密钥模式。

**属性说明**

| **属性名**   | **值** | **描述**       |
| ------------ | ------ | -------------- |
| INTERNAL_KEY | 0      | 内部密钥模式。 |
| EXTERNAL_KEY | 1      | 外部密钥模式。 |
| UNKNOWN      | 2      | 未知。         |

 

#### 1.1.1.7 KeyManagerRC

**定义**

```c++
enum class KeyManagerRC : int { 
   OK = 0, 
   ERROR = 1, 
   INVALID_PARAM = 2, 
   KEY_EXPIRED = 3, 
   UNINITED = 4, 
   INIT_FAILED = 5,
   DOMAIN_COUNT_INVALID,
   KEY_ACTIVE_FAILED, 
   UNSUPPORTED, 
 };
```

**用途**

Key Management 密钥管理错误码。

**属性说明**

| **名称**             | **值** | **含义**        |
| -------------------- | ------ | --------------- |
| OK                   | 0      | 成功            |
| ERROR                | 1      | 失败            |
| INVALID_PARAM        | 2      | 参数无效        |
| KEY_EXPIRED          | 3      | 密钥过期        |
| UNINITED             | 4      | 未初始化        |
| INIT_FAILED          | 5      | 初始化失败      |
| DOMAIN_COUNT_INVALID | 6      | domainCount无效 |
| KEY_ACTIVE_FAILED    | 7      | 激活密钥失败    |
| UNSUPPORTED          | 8      | 不支持          |

 

#### 1.1.1.8 KeyManagerTy

**定义**

```c++
enum class KeyManagerTy : int { 
   OPENBAO = 0, 
   VAULT = 1, 
   UNKNOWN = 2, 
 };
```

**用途**

KeyManager类型。

**属性说明**

| **名称** | **值** | **含义**          |
| -------- | ------ | ----------------- |
| OPENBAO  | 0      | OPENBAO密钥管理。 |
| VAULT    | 1      | VAULT密钥管理。   |
| UNKNOWN  | 2      | 未知。            |



#### 1.1.1.9 KrbRc

**定义**

```c++
enum class KrbRc : int { 
   CDF_OK = 0, 
   CDF_ERROR = 1, 
   CDF_INVALID_PARAM = 2, 
   CDF_KEY_EXPIRED = 3, 
   CDF_UNINITED = 4, 
 };
```

**用途**

鉴权kerberos接口错误码。

**属性说明**

| **名称**          | **值** | **含义** |
| ----------------- | ------ | -------- |
| CDF_OK            | 0      | 成功     |
| CDF_ERROR         | 1      | 失败     |
| CDF_INVALID_PARAM | 2      | 参数无效 |
| CDF_KEY_EXPIRED   | 3      | 密钥过期 |
| CDF_UNINITED      | 4      | 未初始化 |



#### 1.1.1.10 CcsecCipherSuite

**定义**

```c++
enum class CcsecCipherSuite { 
   CCSEC_AES_GCM_128 = 0, 
   CCSEC_AES_GCM_256 = 1, 
   CCSEC_AES_CCM_128 = 2, 
   CCSEC_CHACHA20_POLY1305 = 3, 
   CCSEC_SM4_CTR = 4, 
   CCSEC_UNSPECIFIED 
 };
```

**用途**

InitCrypto设置算法。

**属性说明**

| **名称**                | **值** | **含义**                |
| ----------------------- | ------ | ----------------------- |
| CCSEC_AES_GCM_128       | 0      | AES_GCM_128算法。       |
| CCSEC_AES_GCM_256       | 1      | AES_GCM_256算法。       |
| CCSEC_AES_CCM_128       | 2      | AES_CCM_128算法。       |
| CCSEC_CHACHA20_POLY1305 | 3      | CHACHA20_POLY1305算法。 |
| CCSEC_SM4_CTR           | 4      | SM4_CTR算法。           |
| CCSEC_UNSPECIFIED       | 5      | 未知算法。              |

 

#### 1.1.1.11 CcsecCryptErrorCode

**定义**

```c++
typedef enum { 
   CCSEC_CRYPT_OK = 0,           // Success 
   CCSEC_CRYPT_ERROR,           // Failed 
   CCSEC_CRYPT_PARAM_INVALID,       // The param is invalid 
   CCSEC_CRYPT_PARAM_DOMAIN_COUNT_INVALID, // the domain count is invalid 
   CCSEC_CRYPT_KMC_INIT_FAILED,      // Init kmc failed 
   CCSEC_CRYPT_KEY_ACTIVE_FAILED, 
 
   CCSEC_OPENSSL_EAL_CIPHER_CTX_NULL, 
   CCSEC_OPENSSL_CRYPT_NULL_INPUT = 0x01010001,       // Null pointer input error, bufferLen is 0. 
   CCSEC_OPENSSL_CRYPT_SECUREC_FAIL,             // Security function returns an error. 
   CCSEC_OPENSSL_CRYPT_MEM_ALLOC_FAIL,            // Failed to apply for memory. 
   CCSEC_OPENSSL_CRYPT_NO_REGIST_RAND,            // The global random number is not registered. 
   CCSEC_OPENSSL_CRYPT_EAL_BUFF_LEN_NOT_ENOUGH = 0x01020001, // Insufficient buffer length. 
   CCSEC_OPENSSL_CRYPT_EAL_ERR_ALGID,            // Incorrect algorithm ID. 
   CCSEC_OPENSSL_CRYPT_EAL_ALG_NOT_SUPPORT,  // Algorithm not supported, algorithm behavior not supported. 
   CCSEC_OPENSSL_CRYPT_EAL_ERR_NOT_REGISTER, // Algorithm function is not registered. 
   CCSEC_OPENSSL_CRYPT_EAL_CIPHER_CTRL_ERROR, // CRYPT_EAL_CipherCtrl interface unsupported CTRL type. 
   /* The usage process is incorrect. For example, run the update command without 
   running the init command. For details, see related algorithms. */ 
   CCSEC_OPENSSL_CRYPT_EAL_ERR_STATE, 
   CCSEC_OPENSSL_CRYPT_EAL_ERR_PART_OVERLAP,  // Some memory overlap. 
   CCSEC_OPENSSL_CRYPT_EAL_ERR_RAND_NO_WORKING, // DRBG is not working. 
 
   CCSEC_OPENSSL_CRYPT_EAL_ERR_GLOBAL_DRBG_NULL, // The global DRBG is null. 
 
   CCSEC_OPENSSL_CRYPT_EAL_ERR_DRBG_REPEAT_INIT, // DRBG is initialized repeatedly. 
   CCSEC_OPENSSL_CRYPT_EAL_ERR_DRBG_INIT_FAIL,  // DRBG initialization failure. 
 
   CCSEC_OPENSSL_CRYPT_MODE_ERR_INPUT_LEN = 0x01030001, // The function input length is not the expected length. 
   CCSEC_OPENSSL_CRYPT_AES_ERR_KEYLEN = 0x01040001,   // Incorrect key length. 
 
   CCSEC_OPENSSL_CRYPT_CMVP_NOT_APPROVED = 0x01050001, // Does not meet the standard requirements. 
   /* In ccm mode, When the ctrl interface is used to set the msg length, the input parameter length or the 
   input parameter data length is incorrect. (This specification is affected by ivLen.) */ 
   CCSEC_OPENSSL_CRYPT_MODES_CTRL_MSGLEN_ERROR = 0x01100001, 
   CCSEC_OPENSSL_CRYPT_PBKDF2_PARAM_ERROR = 0x01150001, // Incorrect input parameter. 
   CCSEC_OPENSSL_CRYPT_PBKDF2_NOT_SUPPORTED       // Does not support the PBKDF2 algorithm. 
 } CcsecCryptErrorCode;
```

**用途**

加解密错误码。

**属性说明**

| **名称**                                     | **值**     | **含义**                                 |
| -------------------------------------------- | ---------- | ---------------------------------------- |
| CCSEC_CRYPT_OK                               | 0          | 成功。                                   |
| CCSEC_CRYPT_ERROR                            | 1          | 失败。                                   |
| CCSEC_CRYPT_PARAM_INVALID                    | 2          | 参数无效。                               |
| CCSEC_CRYPT_PARAM_DOMAIN_COUNT_INVALID       | 3          | domain count无效。                       |
| CCSEC_CRYPT_KMC_INIT_FAILED                  | 4          | 初始化KM失败。                           |
| CCSEC_CRYPT_KEY_ACTIVE_FAILED                | 5          | 激活KM密钥失败                           |
| CCSEC_OPENSSL_EAL_CIPHER_CTX_NULL            | 0x01010000 | 初始化加解密ctx为NULL。                  |
| CCSEC_OPENSSL_CRYPT_NULL_INPUT               | 0x01010001 | 加解密入参为NULL。                       |
| CCSEC_OPENSSL_CRYPT_SECUREC_FAIL             | 0x01010002 | 安全函数返回一个错误。                   |
| CCSEC_OPENSSL_CRYPT_MEM_ALLOC_FAIL           | 0x01010003 | 申请内存失败。                           |
| CCSEC_OPENSSL_CRYPT_NO_REGIST_RAND           | 0x01010004 | 全局随机数没有注册。                     |
| CCSEC_OPENSSL_CRYPT_EAL_BUFF_LEN_NOT_ENOUGH  | 0x01020001 | 不足的缓冲长度。                         |
| CCSEC_OPENSSL_CRYPT_EAL_ERR_ALGID            | 0x01020002 | 错误的算法ID。                           |
| CCSEC_OPENSSL_CRYPT_EAL_ALG_NOT_SUPPORT      | 0x01020003 | 不支持的算法。                           |
| CCSEC_OPENSSL_CRYPT_EAL_ERR_NOT_REGISTER     | 0x01020004 | 算法函数未注册。                         |
| CCSEC_OPENSSL_CRYPT_EAL_CIPHER_CTRL_ERROR    | 0x01020005 | CRYPT_EAL_CipherCtrl接口不支持CTRL类型。 |
| CCSEC_OPENSSL_CRYPT_EAL_ERR_STATE            | 0x01020006 | CRYPT_EAL_ERR。                          |
| CCSEC_OPENSSL_CRYPT_EAL_ERR_PART_OVERLAP     | 0x01020007 | 内存重叠。                               |
| CCSEC_OPENSSL_CRYPT_EAL_ERR_RAND_NO_WORKING  | 0x01020008 | DRBG没有正常工作。                       |
| CCSEC_OPENSSL_CRYPT_EAL_ERR_GLOBAL_DRBG_NULL | 0x01020009 | 全局DRBG是null。                         |
| CCSEC_OPENSSL_CRYPT_EAL_ERR_DRBG_REPEAT_INIT | 0x01020010 | DRBG重复初始化。                         |
| CCSEC_OPENSSL_CRYPT_EAL_ERR_DRBG_INIT_FAIL   | 0x01020011 | DRBG初始化失败。                         |
| CCSEC_OPENSSL_CRYPT_MODE_ERR_INPUT_LEN       | 0x01030001 | 函数入参长度不符和预期。                 |
| CCSEC_OPENSSL_CRYPT_AES_ERR_KEYLEN           | 0x01040001 | keyLen错误。                             |
| CCSEC_OPENSSL_CRYPT_CMVP_NOT_APPROVED        | 0x01050001 | 不符合标准要求。                         |
| CCSEC_OPENSSL_CRYPT_MODES_CTRL_MSGLEN_ERRO   | 0x01100001 | msg长度错误。                            |
| CCSEC_OPENSSL_CRYPT_PBKDF2_PARAM_ERROR       | 0x01150001 | 错误的入参。                             |
| CCSEC_OPENSSL_CRYPT_PBKDF2_NOT_SUPPORTED     | 0x01150002 | 不支持PBKDF2算法.                        |

 

#### 1.1.1.12 CcsecCryptMacAlgId

**定义**

```c++
enum class CcsecCryptMacAlgId { 
   CCSEC_CRYPT_MAC_HMAC_SHA256, 
   CCSEC_CRYPT_MAC_HMAC_SHA384, 
   CCSEC_CRYPT_MAC_HMAC_SHA512, 
   CCSEC_CRYPT_MAC_HMAC_SM3 
 };
```

**用途**

设置PBKDF2算法ID。

**属性说明**

| **名称**                    | **值** | **含义** |
| --------------------------- | ------ | -------- |
| CCSEC_CRYPT_MAC_HMAC_SHA256 | 0      | SHA256。 |
| CCSEC_CRYPT_MAC_HMAC_SHA384 | 1      | SHA384。 |
| CCSEC_CRYPT_MAC_HMAC_SHA512 | 2      | SHA512。 |
| CCSEC_CRYPT_MAC_HMAC_SM3    | 3      | SM3。    |

 

#### 1.1.1.13 LogRc

**定义**

```c++
enum class LogRc { 
   SUCCESS = 0, 
   INVALID_PARAM, 
   INITIALIZED_FAILED, 
   INVALID_LEVEL 
 };
```

**用途**

日志错误代码。

**属性说明**

| **名称**           | **值** | **含义**   |
| ------------------ | ------ | ---------- |
| SUCCESS            | 0      | 成功       |
| INVALID_PARAM      | 1      | 无效的参数 |
| INITIALIZED_FAILED | 2      | 初始化失败 |
| INVALID_LEVEL      | 3      | 无效的级别 |

 

#### 1.1.1.14 LogLevel

**定义**

```c++
enum class LogLevel { 
   LOG_LEVEL_TRACE = 0, 
   LOG_LEVEL_DEBUG = 1,  
   LOG_LEVEL_INFO = 2,   
   LOG_LEVEL_WARN = 3,   
   LOG_LEVEL_ERROR = 4,  
   LOG_LEVEL_CRITICAL = 5 
 };
```

**用途**

日志级别。

**属性说明**

| **名称**           | **值** | **含义**                           |
| ------------------ | ------ | ---------------------------------- |
| LOG_LEVEL_TRACE    | 0      | TRACE级别日志。                    |
| LOG_LEVEL_DEBUG    | 1      | DEBUG级别日志。                    |
| LOG_LEVEL_INFO     | 2      | INFO级别日志。                     |
| LOG_LEVEL_WARN     | 3      | WARN级别日志。                     |
| LOG_LEVEL_ERROR    | 4      | ERROR级别日志。                    |
| LOG_LEVEL_CRITICAL | 5      | CRITICAL级别日志，该级别不打日志。 |

 

#### 1.1.1.15 PskManagerRC

**定义**

```c++
enum class PskManagerRC : int { 
   OK, 
   ERROR, 
   INVALID_PARAM, 
   UNINITED, 
   INIT_FAILED, 
   PSK_NOT_EXIST, 
   UNSUPPORTED, 
   PSK_HAS_EXPIRED, 
   ENCRYPTO_FAIL, 
   DECRYPTO_FAIL, 
   CALL_BACK_UNREGISTED, 
   CALL_BACK_EXECUTE_FAILED, 
   CALL_BACK_REGISTER_FAILED, 
   CALL_BACK_TYPE_MISMATCH, 
   CALL_BACK_STANDARD_LIBRARY_EXCEPTION, 
   CALL_BACK_UN_KNOWN, 
 };
```

**用途**

PskManagerRC为接口退出码枚举类。

**属性说明**

| **名称**                             | **值** | **含义**               |
| ------------------------------------ | ------ | ---------------------- |
| OK                                   | 0      | 成功。                 |
| ERROR                                | 1      | 失败。                 |
| INVALID_PARAM                        | 2      | 参数无效。             |
| UNINITED                             | 3      | 未初始化。             |
| INIT_FAILED                          | 4      | 初始化失败。           |
| PSK_NOT_EXIST                        | 5      | PSK不存在。            |
| UNSUPPORTED                          | 6      | 不支持。               |
| PSK_HAS_EXPIRED                      | 7      | PSK已过期。            |
| ENCRYPTO_FAIL                        | 8      | 加密失败               |
| DECRYPTO_FAIL                        | 9      | 解密失败               |
| CALL_BACK_UNREGISTED                 | 10     | 回调函数未注册         |
| CALL_BACK_EXECUTE_FAILED             | 11     | 回调函数执行失败       |
| CALL_BACK_REGISTER_FAILED            | 12     | 回调函数注册失败       |
| CALL_BACK_TYPE_MISMATCH              | 13     | 回调函数类型不匹配     |
| CALL_BACK_STANDARD_LIBRARY_EXCEPTION | 14     | 标准库异常             |
| CALL_BACK_UN_KNOWN                   | 15     | 未知异常（如内存错误） |

 

#### 1.1.1.16 PskCallBackType

**定义**

```c++
enum class PskCallBackType : int { 
   CREATE_PSK = 0, 
   UPDATE_PSK = 1, 
   DELETE_PSK = 2, 
 };
```

**用途**

Psk回调函数类型。

**属性说明**

| **名称**   | **值** | **含义**  |
| ---------- | ------ | --------- |
| CREATE_PSK | 0      | 创建PSK。 |
| UPDATE_PSK | 1      | 更新PSK。 |
| DELETE_PSK | 2      | 删除PSK。 |

 

### 1.1.2 结构体

#### 1.1.2.1 CDFDistAuthServerOptions

**定义**

```c++
struct CDFDistAuthServerOptions { 
   JwtAuthMode keyTransferMode = JwtAuthMode::INTERNAL_KEY; 
   int16_t tokenExpireMinutes = 480; 
   CryptoHmacAlg algType = CryptoHmacAlg::HMAC_SHA256; 
   KeyManagerTy keyManagerType = KeyManagerTy::OPENBAO;
   int16_t serverKeyExpiredHours = 24; 
   int16_t domainCount = 2; 
   int16_t domainId = 0; 
   std::string execPath;
   std::string accessToken;
 };
```

**用途**

启动分布式鉴权服务入参，用于配置鉴权服务配置。

**属性说明**

| **属性名**            | **数据类型**  | **描述**                                                     |
| --------------------- | ------------- | ------------------------------------------------------------ |
| keyTransferMode       | JwtAuthMode   | 密钥传输模式，默认值为JwtAuthMode::INTERNAL_KEY，可选值具体请参见JwtAuthMode对应章节。 |
| tokenExpireMinutes    | int16_t       | Token过期时间。单位为“分钟”，范围：[-1, 32767]。默认值为480；-1表示无限期；0表示立即过期。 |
| algType               | CryptoHmacAlg | 算法类型，默认值为CryptoHmacAlg::HMAC_SHA256，可选值具体请参见CryptoHmacAlg对应章节。 |
| keyManagerType        | KeyManagerTy  | 使用的密钥管理方式类型，默认值为OPENBAO，可选值请参见KeyManagerTy对应章节。 |
| serverKeyExpiredHours | int16_t       | 服务端密钥过期时间，单位：小时，范围：[-1, 32767]。默认值为24；-1表示无限期；0表示立即过期。若keyTransferMode为JwtAuthMode::INTERNAL_KEY，则需设置该参数。 |
| domainCount           | int16_t       | domain数，默认值为2，范围：[2,  1023]。若keyTransferMode为 JwtAuthMode::INTERNAL_KEY，则需设置该参数。 |
| domainId              | int16_t       | domain ID，默认值为0，范围：大于等于0，小于domainCount。若keyTransferMode为JwtAuthMode::INTERNAL_KEY，则需设置该参数。 |
| execPath              | string        | 执行的二进制路径                                             |
| accessToken           | string        | openbao/vault生成的token                                     |

 

#### 1.1.2.2 CDFDistAuthCreateTokenOptions

**定义**

```c++
struct CDFDistAuthCreateTokenOptions { 
   const char *key = nullptr; 
   uint32_t keyLen = 0; 
   const char *input = nullptr; 
   uint32_t inputLen = 0; 
   char *token = nullptr; 
   uint32_t tokenLen = 0; 
 };
```

**用途**

分布式鉴权创建Token配置。

**属性说明**

| **属性名** | **数据类型** | **描述**                                                     |
| ---------- | ------------ | ------------------------------------------------------------ |
| key        | char         | 密钥，实际长度需与keyLen一致。                               |
| keyLen     | uint32_t     | 密钥长度。  根据选择的algType，密钥长度范围如下：   HMAC_SHA256，密钥长度范围：[32,1024 *1024 * 100]     \|      HMAC_SHA384，密钥长度范围：[48,1024 *1024 * 100]    \|   HMAC_SHA512，密钥长度范围：[64,1024 *1024 * 100] |
| input      | char         | 创建Token的数据，实际长度需与inputLen一致。                  |
| inputLen   | uint32_t     | 创建Token的数据的长度，支持小于等于104857600长度。           |
| token      | char         | 生成的Token。                                                |
| tokenLen   | uint32_t     | 生成的Token的长度。                                          |

 

#### 1.1.2.3 CDFDistAuthValidateTokenOptions

**定义**

```c++
struct CDFDistAuthValidateTokenOptions { 
   const char *key = nullptr; 
   uint32_t keyLen = 0; 
   const char *token = nullptr; 
   uint32_t tokenLen = 0; 
 };
```

**用途**

分布式鉴权服务校验Token配置。

**属性说明**

| **属性名** | **数据类型** | **描述**                                                     |
| ---------- | ------------ | ------------------------------------------------------------ |
| key        | char         | 密钥，实际长度需与keyLen一致。                               |
| keyLen     | uint32_t     | 密钥长度。  根据选择的algType，密钥长度范围如下：   HMAC_SHA256，密钥长度范围：[32,1024 *1024 * 100]     \|      HMAC_SHA384，密钥长度范围：[48,1024 *1024 * 100]    \|   HMAC_SHA512，密钥长度范围：[64,1024 *1024 * 100] |
| token      | char         | 被校验的Token，实际长度需与tokenLen一致。                    |
| tokenLen   | uint32_t     | 被校验的Token的长度，支持小于等于104857600长度。             |

 

#### 1.1.2.4 KrbResult

**定义**

```c++
struct KrbResult { 
   uint32_t mResult = 0; 
   std::string mMessage; 
 
   KrbResult() = default; 
   KrbResult(uint32_t result, std::string message) : mResult(result), mMessage(std::move(message)) 
   { 
   } 
 
   KrbResult(KrbRc result, std::string message) : mResult(static_cast<uint32_t>(result)), mMessage(std::move(message)) 
   { 
   } 
 
   ~KrbResult() = default; 
 
   KrbRc GetKrbRc() const 
   { 
     return static_cast<KrbRc>(mResult); 
   } 
 
   bool OK() const 
   { 
     return mResult == 0; 
   } 
 };
```

**用途**

鉴权kerberos接口返回结构体。

**属性说明**

| **属性名** | **数据类型** | **描述**                          |
| ---------- | ------------ | --------------------------------- |
| mResult    | uint32_t     | 错误码，具体请参见KrbRc对应章节。 |
| mMessage   | std::string  | 错误信息。                        |

 

#### 1.1.2.5 Pbkdf2ConfigStruct

**定义**

```c++
struct Pbkdf2ConfigStruct { 
   CcsecCryptMacAlgId ccsecCryptMacAlgId{CcsecCryptMacAlgId::CCSEC_CRYPT_MAC_HMAC_SHA256}; 
   uint32_t iterationTimes{100000}; 
   uint32_t outLen{64}; 
   std::vector<uint8_t> salt; 
 };
```

**用途**

传递PBKDF2算发的相关信息，算法ID，迭代次数，密钥派生长度，盐值，作为Pbkdf2Hmac接口入参时，要求见下表。

**属性说明**

| **属性名**         | **数据类型**         | **描述**                                           |
| ------------------ | -------------------- | -------------------------------------------------- |
| ccsecCryptMacAlgId | CcsecCryptMacAlgId   | 算法ID，参见CcsecCryptMacAlgId对应章节。           |
| iterationTimes     | uint32_t             | 迭代次数。取值范围 [1000,  20000000]，默认100000。 |
| outLen             | uint32_t             | 密钥派生长度。 取值范围 [32, 128]，默认64。        |
| salt               | std::vector<uint8_t> | 盐值。长度范围 [16, 64]。                          |

 

#### 1.1.2.6 KeyInfo

**定义**

```c++
struct KeyInfo { 
   uint32_t domainId; 
   uint32_t keyId; 
   std::string status; 
   std::string createTime; 
   std::string expiredTime; 
 };
```

**用途**

Kmc密钥管理获取密钥信息接口返回结构体，属性说明见下表。

**属性说明**

| **属性名**  | **数据类型** | **描述**                                                     |
| ----------- | ------------ | ------------------------------------------------------------ |
| domainId    | uint32_t     | 作用域ID                                                     |
| keyId       | uint32_t     | 密钥ID                                                       |
| status      | std::string  | 密钥状态 ACTIVE:生效  l   INACTIVE:失效  l   TOBEACTIVE:待生效 |
| createTime  | std::string  | 密钥创建时间，格式如：YYYY/MM/DD HH:MM:SS                    |
| expiredTime | std::string  | 密钥过期时间，格式如：YYYY/MM/DD HH:MM:SS                    |

 

#### 1.1.2.7 Psk

**定义**

```c++
class Psk { 
 private: 
   uint32_t pskId; 
   std::string issuer; 
   std::string subject; 
   uint32_t pskLength; 
   std::vector<uint8_t> pskContent; 
   uint32_t validDays; 
   time_t beginTime; 
   time_t endTime; 
 };
```

**用途**

用于存PSK对象信息。

**属性说明**

| **字段名** | **描述**                               | **类型**             |
| ---------- | -------------------------------------- | -------------------- |
| pskId      | PSK凭证id  范围：[0, 4294967295]       | uint32               |
| issuer     | 签发者  字符串长度范围：[1, 64]        | string               |
| subject    | 使用者  字符串长度范围：[1, 64]        | string               |
| pskLength  | PSK长度  支持256/384/512               | uint32_t             |
| pskContent | PSK凭证                                | std::vector<uint8_t> |
| validDays  | PSK有效期天数  单位：天  范围：[1,365] | uint32_t             |
| beginTime  | 有效期开始时间，符合C 标准库time时间   | time_t               |
| endTime    | 有效期结束时间，符合C 标准库time时间   | time_t               |

 

#### 1.1.2.8 PskMetaData

**定义**

```c++
struct PskMetaData { 
   uint32_t pskId; 
   std::string issuer; 
   std::string subject; 
   uint32_t pskLength; 
   uint32_t validDays; 
   time_t beginTime; 
   time_t endTime; 
 };
```

**用途**

用于返回PSK Meta信息。

**属性说明**

| **字段名** | **描述**                               | **类型** |
| ---------- | -------------------------------------- | -------- |
| pskId      | PSK凭证id  范围：[0, 4294967295]       | uint32   |
| issuer     | 签发者  字符串长度范围：[1, 64]        | string   |
| subject    | 使用者  字符串长度范围：[1, 64]        | string   |
| pskLength  | PSK长度  支持256/384/512               | uint32_t |
| validDays  | PSK有效期天数  单位：天  范围：[1,365] | uint32_t |
| beginTime  | 有效期开始时间，符合C 标准库time时间   | time_t   |
| endTime    | 有效期结束时间，符合C 标准库time时间   | time_t   |

 

#### 1.1.2.9 PskParam

**定义**

```c++
struct PskParam { 
   std::string issuer; 
   std::string subject; 
   uint32_t pskLength; 
   time_t beginTime; 
   uint32_t validDays 
 };
```

**用途**

用于生成、导入PSK凭证接口传入属性参数结构。

**属性说明**

| **字段名** | **描述**                               | **类型** |
| ---------- | -------------------------------------- | -------- |
| issuer     | 签发者  字符串长度范围：[1, 64]        | string   |
| subject    | 使用者  字符串长度范围：[1, 64]        | string   |
| pskLength  | PSK长度  支持256/384/512               | uint32_t |
| validDays  | PSK有效期天数  单位：天  范围：[1,365] | uint32_t |
| beginTime  | 有效期开始时间，符合C 标准库time时间   | time_t   |

 

#### 1.1.2.10 PsKManagerInitOptions

**定义**

```c++
struct PsKManagerInitOptions {
    /* algorithm for secure , enum in see CryptoSymAlg */
    CryptoSymAlg algType = CryptoSymAlg::AES256_GCM;
    /* km option, default openbao */
    KeyManagerTy keyManagerType = KeyManagerTy::OPENBAO;
    /* openbao or vault exePath */
    std::string_view exePath;
    /* openbao or vault accessToken */
    std::string_view accessToken;
    /* domain count */
    uint32_t domainCount = 2;
    /* domain id */
    uint32_t domainId = 0;
    /* PSK max count */
    uint32_t pskMaxCount = 100000;
};
```

**用途**

用于Psk管理初始化传入选项参数结构。

**属性说明**

| 字段名         | 描述                                                         | 类型         |
| -------------- | ------------------------------------------------------------ | ------------ |
| algType        | 算法类型，枚举选项参考CryptoSymAlg章节。  仅支持CryptoSymAlg::AES256_GCM、CryptoSymAlg::CHACHA20_POLY1305。 | CryptoSymAlg |
| keyManagerType | 密钥管理类型，参考KeyManagerTy对应章节                       | KeyManagerTy |
| exePath        | 执行的二进制路径                                             | string_view  |
| accessToken    | openbao/vault生成的token                                     | string_view  |
| domainCount    | domain数，默认值为2，范围：[2,  1023]。                      | int16_t      |
| domainId       | domain ID，默认值为0，范围：大于等于0，小于domainCount，且不能为1。 | int16_t      |
| pskMaxCount    | PSK凭证生成或导入最大数量（包含已删除），默认值：100000，范围：[1, 4294967295] | uint32_t     |

 

### 1.1.3 变量

#### 1.1.3.1 log level

```c++
const int CCSEC_LOG_TRACE = 0; 
const int CCSEC_LOG_DEBUG = 1; 
const int CCSEC_LOG_INFO = 2; 
const int CCSEC_LOG_WARN = 3; 
const int CCSEC_LOG_ERROR = 4; 
const int CCSEC_LOG_LEVEL_MAX = 5;
```

| **名称**            | **值** | **含义**                       |
| ------------------- | ------ | ------------------------------ |
| CCSEC_LOG_TRACE     | 0      | trace级别日志                  |
| CCSEC_LOG_DEBUG     | 1      | debug级别日志                  |
| CCSEC_LOG_INFO      | 2      | info级别日志                   |
| CCSEC_LOG_WARN      | 3      | warn级别日志                   |
| CCSEC_LOG_ERROR     | 4      | error级别日志                  |
| CCSEC_LOG_LEVEL_MAX | 5      | 最大日志级别，该级别不打印日志 |

# 2 API 接口

## 2.1 授权

### 2.1.1 白名单授权协议

#### 2.1.1.1 WhitelistAuthorization::Initialize

**函数定义**

白名单认证配置初始化，全局仅需执行一次。

**实现方法**

```c++
AuthRC Initialize(std::string_view conf);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                     |
| ---------- | ------------ | ------------ | ------------------------------------------------------------ |
| conf       | [IN]         | 是           | 白名单配置，格式需为JSON数组字符串，支持不为空且小于等于104857600长度内容，格式参考如下：  [     {      "user":  "user1",      "allow": true     },     {      "user":  "user2",      "allow": false     }    ] |

**返回值**

请参见AuthRC对应章节。



#### 2.1.1.2 WhitelistAuthorization::CheckPermission

**函数定义**

认证鉴权。

**实现方法**

```c++
AuthRC CheckPermission(std::string_view principal, [[maybe_unused]] std::string_view resource, [[maybe_unused]] std::string_view operation);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                     |
| ---------- | ------------ | ------------ | ------------------------------------------------------------ |
| principal  | [IN]         | 是           | 被授权用户名，支持不为空且小于等于1048576长度内容            |
| resource   | [IN]         | 是           | 需要操作的资源（保留参数，用于未来功能扩展，当前版本未启用） |
| operation  | [IN]         | 是           | 操作类型（保留参数，用于未来功能扩展，当前版本未启用）       |

**返回值**

请参见AuthRC对应章节。



#### 2.1.1.3 WhitelistAuthorization::GetAllPrincipals

**函数定义**

获取所有被授权用户。

**实现方法**

```c++
AuthRC GetAllPrincipals(std::vector<std::string> &principals);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**         |
| ---------- | ------------ | ------------ | ---------------- |
| principals | [OUT]        | 是           | 被授权用户名数组 |

**返回值**

请参见AuthRC对应章节。



#### 2.1.1.4 WhitelistAuthorization::UnInitialize

**函数定义**

清理授权信息。

**实现方法**

```c++
AuthRC UnInitialize();
```

**返回值**

请参见AuthRC对应章节。



## 2.2 鉴权

### 2.2.1 JWT Token 鉴权组件

#### 2.2.1.1 JwtAuthServer::Start

**函数定义**

启动JWT Token鉴权服务。

**实现方法**

```c++
JwtAuthRC Start(const CDFDistAuthServerOptions &opt)
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                           |
| ---------- | ------------ | ------------ | -------------------------------------------------- |
| opt        | [IN]         | 是           | 服务配置，具体请参见CDFDistAuthServerOptions章节。 |

**返回值**

请参见JwtAuthRC对应章节。



#### 2.2.1.2 JwtAuthServer::Stop

**函数定义**

停止JWT Token鉴权服务。

**实现方法**

```c++
JwtAuthRC Stop();
```

**返回值**

请参见JwtAuthRC对应章节。



#### 2.2.1.3 JwtAuthServer::RefreshEncryptionKey

**函数定义**

更新加密密钥。

**实现方法**

```c++
JwtAuthRC RefreshEncryptionKey(std::string_view newKey);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                     |
| ---------- | ------------ | ------------ | ------------------------------------------------------------ |
| newKey     | [IN]         | 是           | 密钥  根据JwtAuthServer::Start设置opt的algType，密钥长度范围如下：  l   HMAC_SHA256，密钥长度范围：[32,1024 * 1024)  l   HMAC_SHA384，密钥长度范围：[48,1024 * 1024)  l   HMAC_SHA512，密钥长度范围：[64,1024 * 1024) |

**返回值**

请参见JwtAuthRC对应章节。



#### 2.2.1.4 JwtAuthServer::SetEncryptionKey

**函数定义**

设置加密密钥。

**实现方法**

```c++
JwtAuthRC SetEncryptionKey(std::string_view newKey);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                     |
| ---------- | ------------ | ------------ | ------------------------------------------------------------ |
| newKey     | [IN]         | 是           | 密钥  说明  根据JwtAuthServer::Start设置opt的algType，密钥长度范围如下：  l   HMAC_SHA256，密钥长度范围：[32,1024 * 1024)  l   HMAC_SHA384，密钥长度范围：[48,1024 * 1024)  l   HMAC_SHA512，密钥长度范围：[64,1024 * 1024) |

**返回值**

请参见JwtAuthRC章节。



#### 2.2.1.5 JwtAuthServer::EstimateTokenLength

**函数定义**

获取预估的Token长度。

**实现方法**

```c++
std::pair<JwtAuthRC, uint32_t> EstimateTokenLength(uint32_t inputLen);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                               |
| ---------- | ------------ | ------------ | ------------------------------------------------------ |
| inputLen   | [IN]         | 是           | 输入长度，范围：大于等于0，小于等于1024 * 1024 * 100。 |

**返回值**

std::pair<JwtAuthRC, uint32_t> 其中JwtAuthRC请参见对应章节；uint32_t为预估的token长度。



#### 2.2.1.6 JwtAuthServer::CreateToken

**函数定义**

创建Token。

**实现方法**

```c++
JwtAuthRC CreateToken(CDFDistAuthCreateTokenOptions &options)
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                     |
| ---------- | ------------ | ------------ | ------------------------------------------------------------ |
| options    | [IN]         | 是           | Token创建配置，具体请参见CDFDistAuthCreateTokenOptions章节。 |

**返回值**

请参见JwtAuthRC章节。



#### 2.2.1.7 JwtAuthServer::ValidateToken

**函数定义**

校验Token。

**实现方法**

```c++
JwtAuthRC ValidateToken(const CDFDistAuthValidateTokenOptions &options)
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                 |
| ---------- | ------------ | ------------ | -------------------------------------------------------- |
| options    | [IN]         | 是           | Token校验配置，参见CDFDistAuthValidateTokenOptions章节。 |

**返回值**

请参见JwtAuthRC章节。



### 2.2.2 Kerberos 鉴权组件

**注意： Kerberos 鉴权组件涉及 API 接口均为非线程安全，请谨慎使用。**

#### 2.2.2.1 KrbClient::ClientInit

**函数定义**

客户端初始化。

**实现方法**

```c++
KrbResult ClientInit(const std::string &inClientName, const std::string &inServiceName, const std::string &keyTable);
```

**参数说明**

| **参数名**    | **参数类型** | **是否必选** | **描述**                                                   |
| ------------- | ------------ | ------------ | ---------------------------------------------------------- |
| inClientName  | [IN]         | 是           | 客户端名称，支持不为空小于等于1048576长度。                |
| inServiceName | [IN]         | 是           | 服务端名称，支持不为空小于等于1048576长度。                |
| keytab        | [IN]         | 是           | 密钥表（用户提供），支持不为空小于等于1024000000长度内容。 |

 **说明：**

+ 该函数的输入值inClientName以及inServiceName均为GSS接口定义下的Principal Name，因此需要满足对应格式“username@REALM”，并且如果在用户/etc/krb5.conf中已经设置了默认的REALM，那么仅输入 “username”时会补充默认的REALM。

+ inClientName, inServiceName不应存在反斜杠，或者多余一个的@符号。

**返回值**

请参见 KrbResult 章节。



#### 2.2.2.2 KrbClient::InitParam

**函数定义**

初始化参数，在ClientInit之后调用。

**实现方法**

```c++
bool InitParam(); 
```

**返回值**

bool。



#### 2.2.2.3 KrbClient::ClientGetCred

**函数定义**

客户端获取凭证。

**实现方法**

```c++
std::pair<KrbResult, std::vector<uint8_t>> ClientGetCred([[maybe_unused]] int flags);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                 |
| ---------- | ------------ | ------------ | -------------------------------------------------------- |
| flags      | [IN]         | 是           | 客户端名称（保留参数，用于未来功能扩展，当前版本未启用） |

**返回值**

std::pair<KrbResult, std::vector<uint8_t>>其中KrbResult参见KrbResult章节；std::vector<uint8_t>为凭证。



#### 2.2.2.4 KrbClient::ClientAuthServer

**函数定义**

客户端执行 authentication，获取结果。

**实现方法**

```c++
KrbResult ClientAuthServer([[maybe_unused]] int flags, char *cred, uint32_t credLen);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                 |
| ---------- | ------------ | ------------ | -------------------------------------------------------- |
| flags      | [IN]         | 是           | 客户端名称（保留参数，用于未来功能扩展，当前版本未启用） |
| cred       | [OUT]        | 是           | 凭证                                                     |
| credLen    | [OUT]        | 是           | 凭证长度                                                 |

**返回值**

具体请参见KrbResult章节。



#### 2.2.2.5 KrbClient::GetAuthentication

**函数定义**

客户端获取鉴权对象。

**实现方法**

```c++
static std::shared_ptr<KrbClient> GetAuthentication(const std::string &name);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                   |
| ---------- | ------------ | ------------ | ---------------------------------------------------------- |
| name       | [IN]         | 是           | 名称，当前仅支持“kerberos”（保留参数，用于未来功能扩展）。 |

**返回值**

KrbClient对象。



#### 2.2.2.6 KrbServer::ServerInit

**函数定义**

服务端初始化。

**实现方法**

```c++
KrbResult ServerInit(const std::string &servicePrincipleName, const std::string &keyTable);
```

**参数说明**

| **参数名**           | **参数类型** | **是否必选** | **描述**                                                   |
| -------------------- | ------------ | ------------ | ---------------------------------------------------------- |
| servicePrincipleName | [IN]         | 是           | 客户端名称，支持不为空小于等于1048576长度。                |
| keytab               | [IN]         | 是           | 密钥表（用户提供），支持不为空小于等于1024000000长度内容。 |

**返回值**

具体请参见KrbResult章节。



#### 2.2.2.7 KrbServer::ServerAuth

**函数定义**

服务端执行鉴权客户端。

**实现方法**

```c++
KrbResult ServerAuth(int flags, const std::string &credIn, char **credOut, uint32_t *credLenOut);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                 |
| ---------- | ------------ | ------------ | -------------------------------------------------------- |
| flags      | [IN]         | 是           | 客户端名称（保留参数，用于未来功能扩展，当前版本未启用） |
| credIn     | [IN]         | 是           | 凭证，支持不为空小于等于1024000000长度内容。             |
| credOut    | [OUT]        | 是           | 获取凭证                                                 |
| credLenOut | [OUT]        | 是           | 获取凭证长度                                             |

**返回值**

具体请参见KrbResult章节。



#### 2.2.2.8 KrbServer::ResetInternalKeyTable

**函数定义**

重置内部KeyTable。

**实现方法**

```c++
bool ResetInternalKeyTable();
```

**返回值**

bool。



#### 2.2.2.9 KrbServer::GetKerberosKeytab

**函数定义**

获取keytab。

**实现方法**

```c++
bool GetKerberosKeytab(const std::string &path, char **outKeyTab, uint32_t *length, bool keyTabEncrypted);
```

**参数说明**

| **参数名**      | **参数类型** | **是否必选** | **描述**                                                     |
| --------------- | ------------ | ------------ | ------------------------------------------------------------ |
| path            | [IN]         | 是           | kerberos的keytab文件路径，支持不为空小于等于4096长度内容。。 |
| outKeyTab       | [OUT]        | 是           | 输出的keytab。                                               |
| length          | [OUT]        | 是           | 输出的keytab长度。                                           |
| keyTabEncrypted | [IN]         | 是           | keytab是否加密。注意，如果加密得先初始化密钥管理软件，auto *km = KeyManagerFactory::Borrow后km->Init。 |

**返回值**

bool。



#### 2.2.2.10 KrbServer::CheckFile

**函数定义**

校验文件是否存在。

**实现方法**

```c++
bool CheckFile(const std::string &configPath);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                     |
| ---------- | ------------ | ------------ | -------------------------------------------- |
| configPath | [IN]         | 是           | 文件路径，支持不为空小于等于4096长度内容。。 |

**返回值**

bool。



#### 2.2.2.11 KrbServer::GetAuthentication

**函数定义**

服务端获取鉴权对象。

**实现方法**

```c++
static std::shared_ptr<KrbServer> GetAuthentication([[maybe_unused]] const std::string &name);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                   |
| ---------- | ------------ | ------------ | ---------------------------------------------------------- |
| name       | [IN]         | 是           | 名称，当前仅支持“kerberos”（保留参数，用于未来功能扩展）。 |

**返回值**

KrbServer对象。



## 2.3 加解密

### 2.3.1 基础加解密接口

#### 2.3.1.1 NativeCryptor::Encrypt

**函数定义**

使用密钥加密算法，将明文进行加密，返回错误码以及加密的结果

**实现方法**

```c++
std::pair<CryptionRC, std::vector<std::byte>> Encrypt(const CryptoSymAlg &alg, std::vector<std::byte> &plaintext, std::vector<std::byte> &key);
```

**参数说明**

| **名称**  | 参数类型 | **说明**                                                     |
| --------- | -------- | ------------------------------------------------------------ |
| alg       | [IN]     | 对称加密算法，类型为CryptoSymAlg                             |
| plaintext | [IN]     | 加密前的明文，长度为(0, 1024 * 1024)                         |
| key       | [IN]     | 加密使用的密钥，CCSEC_AES_GCM_128、CCSEC_AES_CCM_128、CCSEC_SM4_CTR算法对应的长度为128，CCSEC_AES_GCM_256、CCSEC_CHACHA20_POLY1305算法对应的长度为256。 |

**返回值**

前半部分 CryptionRC为枚举值，请参见CryptionRC章节，后半部分为 std::vector\<std::byte> 类型，表示了成功加密的Base64密文，若加密失败，则返回空 empty vector.



#### 2.3.1.2 NativeCryptor::Decrypt

**函数定义**

使用密钥加密算法，将密文进行解密，返回错误码以及解密的结果

**实现方法**

```c++
std::pair<CryptionRC, std::vector<std::byte>> Decrypt(const CryptoSymAlg &alg, std::vector<std::byte> &ciphertext, std::vector<std::byte> &key);
```

**参数说明**

| **名称**   | 参数类型 | **说明**                                                     |
| ---------- | -------- | ------------------------------------------------------------ |
| alg        | [IN]     | 对称加密算法，类型为CryptoSymAlg，请参见对应章节。           |
| ciphertext | [IN]     | 解密前的密文（Base64），长度为(0, 2\*1024\*1024)             |
| key        | [IN]     | 解密使用的密钥，CCSEC_AES_GCM_128、CCSEC_AES_CCM_128、CCSEC_SM4_CTR算法对应的长度为128，CCSEC_AES_GCM_256，CCSEC_CHACHA20_POLY1305算法对应的长度为256。 |

**返回值**

前半部分 CryptionRC为枚举值，请参见CryptionRC章节

后半部分为std::vector\<std::byte>类型，表示了成功解密的明文，若解密失败，则返回 empty vector。



#### 2.3.1.3 Pbkdf2Hmac

**函数定义**

PBKDF2方式进行密钥派生，并将结果进行 base64 转码

**实现方法**

```c++
int32_t Pbkdf2Hmac(const std::vector<uint8_t> &key, const Pbkdf2ConfigStruct &pbkdf2ConfigStruct,std::vector<uint8_t> &outBase64);
```

**参数说明**

| **名称**           | 参数类型 | **说明**                                  |
| ------------------ | -------- | ----------------------------------------- |
| key                | [IN]     | 密钥。密钥长度，范围[0, uint32_t最大值]。 |
| pbkdf2ConfigStruct | [IN]     | 见Pbkdf2ConfigStruct对应章节。            |
| outBase64          | [OUT]    | 输出结果，已Base64转码。                  |

**返回值**

失败返回错误码 成功返回 CCSEC_CRYPT_OK，请参见CcsecCryptErrorCode章节。



#### 2.3.1.4 GetPbkdf2Config

**函数定义**

将Pbkdf2Hmac接口生成的结果解析，将算法id、盐值、迭代次数、密钥派生长度通过Pbkdf2ConfigStruct返回。

**实现方法**

```c++
int32_t GetPbkdf2Config(const std::vector<uint8_t> &base64Code, Pbkdf2ConfigStruct &pbkdf2ConfigStruct);
```

**参数说明**

| **名称**           | 参数类型 | **说明**                        |
| ------------------ | -------- | ------------------------------- |
| base64Code         | [IN]     | Pbkdf2Hmac接口生成的outBase64。 |
| pbkdf2ConfigStruct | [OUT]    | 见Pbkdf2ConfigStruct章节。      |

**返回值**

失败返回错误码 成功返回 CCSEC_CRYPT_OK，请参见CcsecCryptErrorCode章节。



### 2.3.2 基于密钥管理组件的加解密接口

#### 2.3.2.1 KmCryptor

**函数定义**

基于密钥管理组件加解密类的构造函数

**实现方法**

```c++
KmCryptor::KmCryptor(KeyManager *km); 
KmCryptor::KmCryptor(KeyManagerTy type);
```

**参数说明**

| **名称** | 参数类型 | **说明**         |
| -------- | -------- | ---------------- |
| km       | [IN]     | 密钥管理组件指针 |
| type     | [IN]     | 密钥管理组件类型 |



#### 2.3.2.2 KmCryptor::Encrypt

**函数定义**

使用密钥管理组件应用域、加密算法，将明文进行加密，返回错误码以及加密的结果

**实现方法**

```c++
std::pair<CryptionRC, std::vector<std::byte>> Encrypt(CryptoSymAlg alg, 
                      std::vector<std::byte> plaintext, 
                      uint32_t domainId);
```

**参数说明**

| **名称**  | 参数类型 | **说明**                                                     |
| --------- | -------- | ------------------------------------------------------------ |
| alg       | [IN]     | 对称加密算法，类型为CryptoSymAlg，请参见 CryptoSymAlg章节。传参约束以实例化KeyManagerTy类型的同名Encrypt约束为准。 |
| plaintext | [IN]     | 加密前的明文。传参约束以实例化KeyManagerTy类型的同名Encrypt约束为准。 |
| domainId  | [IN]     | 密钥管理组件的应用域。传参约束以实例化KeyManagerTy类型的同名Encrypt约束为准。 |

**返回值**

前半部分CryptionRC请参见CryptionRC章节

后半部分为 std::vector\<std::byte> 类型，表示了成功加密的 base64 密文，若加密失败，则返回空



#### 2.3.2.3 KmCryptor::Decrypt

**函数定义**

使用密钥管理组件应用域、加密算法，将明文进行加密，返回错误码以及加密的结果

**实现方法**

```c++
std::pair<CryptionRC, std::vector<std::byte>> Decrypt(CryptoSymAlg alg, 
                      std::vector<std::byte> ciphertext, 
                      uint32_t domainId);
```

**参数说明**

| **名称**   | 参数类型 | **说明**                                                     |
| ---------- | -------- | ------------------------------------------------------------ |
| alg        | [IN]     | 对称加密算法，类型为CryptoSymAlg，请参见CryptoSymAlg章节。传参约束以实例化KeyManagerTy类型的同名Decryptt约束为准。 |
| ciphertext | [IN]     | 解密前的密文（Base64），传参约束以实例化KeyManagerTy类型的同名Decrypt约束为准。 |
| domainId   | [IN]     | 密钥管理组件的应用域，传参约束以实例化KeyManagerTy类型的同名Decrypt约束为准。 |

**返回值**

前半部分 CryptionRC请参见CryptionRC章节。

后半部分为 std::vector\<std::byte> 类型，表示了成功加密的 base64 密文，若加密失败，则返回空。



## 2.4 密钥管理

**注意：openbao/vault不支持并发。**

### 2.4.1 基于 OPENBAO 的密钥管理

#### 2.4.1.1 OpenbaoKeyManager::Init

**函数定义**

初始化密钥管理。

**实现方法**

```c++
KeyManagerRC Init(std::string_view exePath, std::string_view accessToken, uint32_t domainCount);
```

**参数说明**

| **参数名**  | **参数类型** | **是否必选** | **描述**                     |
| ----------- | ------------ | ------------ | ---------------------------- |
| exePath     | [IN]         | 是           | 执行的二进制路径             |
| accessToken | [IN]         | 是           | openbao生成的token           |
| domainCount | [IN]         | 是           | 作用域数量，在（1,1024）之间 |

**返回值**

请参见KeyManagerRC章节。



#### 2.4.1.2 OpenbaoKeyManager::UnInit

**函数定义**

反初始化密钥管理。

**实现方法**

```c++
KeyManagerRC UnInit();
```

**返回值**

请参见KeyManagerRC章节。



#### 2.4.1.3 OpenbaoKeyManager::CreateKey

**函数定义**

创建密钥。

**实现方法**

```c++
std::pair<KeyManagerRC, uint32_t> CreateKey(uint32_t domainId);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                           |
| ---------- | ------------ | ------------ | ---------------------------------- |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。 |

**返回值**

错误码。请参见KeyManagerRC章节。

密钥ID，若创建密钥失败，返回0。注：1.生成密钥ID最大为65535，若超出该值则会创建失败。2.密钥数量最多存在1022个，若超出该数量则会创建失败。



#### 2.4.1.4 OpenbaoKeyManager::RemoveKey

**函数定义**

删除密钥。

**实现方法**

```c++
KeyManagerRC RemoveKey(uint32_t domainId, uint32_t keyId);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                           |
| ---------- | ------------ | ------------ | -------------------------------------------------- |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。                 |
| keyId      | [IN]         | 是           | 密钥ID，取值为[0, 65535]，密钥数量最多存在1022个。 |

**返回值**

请参见 KeyManagerRC章节。



#### 2.4.1.5 OpenbaoKeyManager::DisplayAllKey

**函数定义**

展示所有密钥。

**实现方法**

```c++
KeyManagerRC DisplayAllKey();
```

**返回值**

请参见KeyManagerRC章节。



#### 2.4.1.6 OpenbaoKeyManager::DisplayKey

**函数定义**

展示密钥。

**实现方法**

```c++
KeyManagerRC DisplayKey(uint32_t domainId);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                           |
| ---------- | ------------ | ------------ | ---------------------------------- |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。 |

**返回值**

请参见KeyManagerRC章节。



#### 2.4.1.7 OpenbaoKeyManager::DeleteAllKey

**函数定义**

删除所有密钥。

**实现方法**

```c++
KeyManagerRC DeleteAllKey();
```

**返回值**

请参见KeyManagerRC章节。



#### 2.4.1.8 OpenbaoKeyManager::CheckDomainKeysExpired

**函数定义**

校验密钥是否过期。

**实现方法**

```c++
KeyManagerRC CheckDomainKeysExpired(uint32_t domainId, uint32_t lead);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                            |
| ---------- | ------------ | ------------ | ----------------------------------- |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。  |
| lead       | [IN]         | 是           | 提前时间量，单位为天，小于等于5年。 |

**返回值**

请参见KeyManagerRC章节。



#### 2.4.1.9 OpenbaoKeyManager::CheckDomainKeysExpiredAndAutoUpdate

**函数定义**

校验密钥是否过期并自动更新。

**实现方法**

```c++
KeyManagerRC CheckDomainKeysExpiredAndAutoUpdate(uint32_t domainId, uint32_t lead);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                            |
| ---------- | ------------ | ------------ | ----------------------------------- |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。  |
| lead       | [IN]         | 是           | 提前时间量，单位为天，小于等于5年。 |

**返回值**

请参见KeyManagerRC章节。



#### 2.4.1.10 OpenbaoKeyManager::Encrypt

**函数定义**

加密。

**实现方法**

```c++
std::pair<KeyManagerRC, std::vector<std::byte>> Encrypt(const CryptoSymAlg &symAlg, uint32_t domainId, std::string_view plaintext); 
std::pair<KeyManagerRC, std::vector<std::byte>> Encrypt(uint32_t domainId, std::string_view plaintext);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                     |
| ---------- | ------------ | ------------ | ------------------------------------------------------------ |
| symAlg     | [IN]         | 是           | 对称加密算法，类型为CryptoSymAlg，支持 AES256_GCM,CHACHA20_POLY1305。 |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。                           |
| plaintext  | [IN]         | 是           | 要加密的明文，不能为空，长度小于1024 * 1024。注意 KeyManager 在此处不会清理内存，用户需自行处理。 |

注意：加解密接口允许使用过期密钥进行加解密。

**返回值**

KeyManagerRC错误码，请参见KeyManagerRC章节。

std::vector\<std::byte>，加密后的密文。



#### 2.4.1.11 OpenbaoKeyManager::Decrypt

**函数定义**

解密。

**实现方法**

```c++
std::pair<KeyManagerRC, std::vector<std::byte>> Decrypt(const CryptoSymAlg &symAlg, uint32_t domainId, std::string_view ciphertext); 
 std::pair<KeyManagerRC, std::vector<std::byte>> Decrypt(uint32_t domainId, std::string_view ciphertext);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                     |
| ---------- | ------------ | ------------ | ------------------------------------------------------------ |
| symAlg     | [IN]         | 是           | 对称加密算法，类型为CryptoSymAlg，支持 AES256_GCM,CHACHA20_POLY1305。 |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。                           |
| ciphertext | [IN]         | 是           | 要解密的密文，不能为空，长度小于2 * 1024 *1024。注意 KeyManager 在此处不会清理内存，用户需自行处理。 |

注意：加解密接口允许使用过期密钥进行加解密。

**返回值**

KeyManagerRC错误码，请参见KeyManagerRC章节。

std::vector\<std::byte>，解密后的明文。



#### 2.4.1.12 OpenbaoKeyManager::Type

**函数定义**

返回当前 KeyManager 类型。

**实现方法**

```c++
KeyManagerTy Type();
```

**返回值**

KeyManagerTy::OPENBAO



#### 2.4.1.13 OpenbaoKeyManager::DomainCount

**函数定义**

返回当前 KeyManager 所支持的 最大 domain count。

**实现方法**

```c++
uint32_t DomainCount();
```

**返回值**

uint32_t domainCount，作用域的数量



#### 2.4.1.14 OpenbaoKeyManager::CheckInited

**函数定义**

检查当前是否初始化过

**实现方法**

```c++
bool CheckInited();
```

**返回值**

bool值，false为未初始化，true为已初始化。



#### 2.4.1.15 OpenbaoKeyManager::SetType

**函数定义**

设置密钥类型

**实现方法**

```c++
void SetType(KeyManagerTy type);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                               |
| ---------- | ------------ | ------------ | -------------------------------------- |
| type       | [IN]         | 是           | KeyManager类型，请参见KeyManagerTy章节 |

**返回值**

void



#### 2.4.1.16 OpenbaoKeyManager::GetLatestKey

**函数定义**

获取密钥。

**实现方法**

```c++
std::vector<std::byte> GetLatestKey(uint32_t domainId, uint32_t &keyId);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                           |
| ---------- | ------------ | ------------ | ---------------------------------- |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。 |
| keyId      | [OUT]        | 否           | 成功时为密钥id                     |

**返回值**

domainId的最后一个密钥，错误时为空。



#### 2.4.1.17 OpenbaoKeyManager::GetInstance

**函数定义**

获取唯一实例。

**实现方法**

```c++
static OpenbaoKeyManager &GetInstance();
```

**返回值**

OpenbaoKeyManager。



#### 2.4.1.18 OpenbaoKeyManager::BorrowInstance

**函数定义**

获取KeyManager实例的指针。

**实现方法**

```c++
static OpenbaoKeyManager *BorrowInstance();
```

**返回值**

OpenbaoKeyManager*



### 2.4.2 基于 VAULT 的密钥管理

#### 2.4.2.1 VaultKeyManager::Init

**函数定义**

初始化密钥管理。

**实现方法**

```c++
KeyManagerRC Init(std::string_view exePath, std::string_view accessToken, uint32_t domainCount);
```

**参数说明**

| **参数名**  | **参数类型** | **是否必选** | **描述**                     |
| ----------- | ------------ | ------------ | ---------------------------- |
| exePath     | [IN]         | 是           | 执行的二进制路径             |
| accessToken | [IN]         | 是           | vault生成的token             |
| domainCount | [IN]         | 是           | 作用域数量，在（1,1024）之间 |

**返回值**

请参见KeyManagerRC章节。



#### 2.4.2.2 VaultKeyManager::UnInit

**函数定义**

反初始化密钥管理。

**实现方法**

```c++
KeyManagerRC UnInit();
```

**返回值**

请参见KeyManagerRC章节。



#### 2.4.2.3 VaultKeyManager::CreateKey

**函数定义**

创建密钥。

**实现方法**

```c++
std::pair<KeyManagerRC, uint32_t> CreateKey(uint32_t domainId);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                           |
| ---------- | ------------ | ------------ | ---------------------------------- |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。 |

**返回值**

KeyManagerRC，错误码。请参见KeyManagerRC章节。

uint32_t，密钥ID，若创建密钥失败，返回0。注：1.生成密钥ID最大为65535，若超出该值则会创建失败。2.密钥数量最多存在1022个，若超出该数量则会创建失败。



#### 2.4.2.4 VaultKeyManager::RemoveKey

**函数定义**

删除密钥。

**实现方法**

```c++
KeyManagerRC RemoveKey(uint32_t domainId, uint32_t keyId);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                           |
| ---------- | ------------ | ------------ | -------------------------------------------------- |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。                 |
| keyId      | [IN]         | 是           | 密钥ID，取值为[0, 65535]，密钥数量最多存在1022个。 |

**返回值**

请参见KeyManagerRC章节。



#### 2.4.2.5 VaultKeyManager::DisplayAllKey

**函数定义**

展示所有密钥。

**实现方法**

```c++
KeyManagerRC DisplayAllKey();
```

**返回值**

请参见KeyManagerRC章节。



#### 2.4.2.6 VaultKeyManager::DisplayKey

**函数定义**

展示密钥。

**实现方法**

```c++
KeyManagerRC DisplayKey(uint32_t domainId);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                           |
| ---------- | ------------ | ------------ | ---------------------------------- |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。 |

**返回值**

请参见KeyManagerRC章节。



#### 2.4.2.7 VaultKeyManager::DeleteAllKey

**函数定义**

删除所有密钥。

**实现方法**

KeyManagerRC DeleteAllKey();

**返回值**

请参见KeyManagerRC章节。



#### 2.4.2.8 VaultKeyManager::CheckDomainKeysExpired

**函数定义**

校验密钥是否过期。

**实现方法**

```c++
KeyManagerRC CheckDomainKeysExpired(uint32_t domainId, uint32_t lead);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                            |
| ---------- | ------------ | ------------ | ----------------------------------- |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。  |
| lead       | [IN]         | 是           | 提前时间量，单位为天，小于等于5年。 |

**返回值**

请参见KeyManagerRC章节。



#### 2.4.2.9 VaultKeyManager::CheckDomainKeysExpiredAndAutoUpdate

**函数定义**

校验密钥是否过期并自动更新。

**实现方法**

```c++
KeyManagerRC CheckDomainKeysExpiredAndAutoUpdate(uint32_t domainId, uint32_t lead);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                            |
| ---------- | ------------ | ------------ | ----------------------------------- |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。  |
| lead       | [IN]         | 是           | 提前时间量，单位为天，小于等于5年。 |

**返回值**

请参见KeyManagerRC章节。



#### 2.4.2.10 VaultKeyManager::Encrypt

**函数定义**

加密。

**实现方法**

```c++
std::pair<KeyManagerRC, std::vector<std::byte>> Encrypt(const CryptoSymAlg &symAlg, uint32_t domainId, std::string_view plaintext); 
std::pair<KeyManagerRC, std::vector<std::byte>> Encrypt(uint32_t domainId, std::string_view plaintext);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                     |
| ---------- | ------------ | ------------ | ------------------------------------------------------------ |
| symAlg     | [IN]         | 是           | 对称加密算法，类型为CryptoSymAlg，支持 AES256_GCM,CHACHA20_POLY1305。 |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。                           |
| plaintext  | [IN]         | 是           | 要加密的明文，不能为空，长度小于1024 * 1024。注意 KeyManager 在此处不会清理内存，用户需自行处理。 |

注意：加解密接口允许使用过期密钥进行加解密。

**返回值**

KeyManagerRC，错误码。请参见KeyManagerRC章节。

std::vector\<std::byte>，加密后的密文。



#### 2.4.2.11 VaultKeyManager::Decrypt

**函数定义**

解密。

**实现方法**

```c++
std::pair<KeyManagerRC, std::vector<std::byte>> Decrypt(const CryptoSymAlg &symAlg, uint32_t domainId, std::string_view ciphertext); 
std::pair<KeyManagerRC, std::vector<std::byte>> Decrypt(uint32_t domainId, std::string_view ciphertext);
```

参数说明

| **参数名** | **参数类型** | **是否必选** | **描述**                                                     |
| ---------- | ------------ | ------------ | ------------------------------------------------------------ |
| symAlg     | [IN]         | 是           | 对称加密算法，类型为CryptoSymAlg，支持 AES256_GCM,CHACHA20_POLY1305。 |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。                           |
| ciphertext | [IN]         | 是           | 要解密的密文，不能为空，长度小于2 * 1024 * 1024。注意 KeyManager 在此处不会清理内存，用户需自行处理。 |

注意：加解密接口允许使用过期密钥进行加解密。

**返回值**

KeyManagerRC，错误码。请参见KeyManagerRC章节。

std::vector\<std::byte>，解密后的明文。



#### 2.4.2.12 VaultKeyManager::Type

**函数定义**

返回当前 KeyManager 类型。

**实现方法**

```c++
KeyManagerTy Type();
```

**返回值**

KeyManagerTy::VAULT



#### 2.4.2.13 VaultKeyManager::DomainCount

**函数定义**

返回当前 KeyManager 所支持的 最大 domain count。

**实现方法**

```c++
uint32_t DomainCount();
```

**返回值**

uint32_t domainCount，作用域的数量



#### 2.4.2.14 VaultKeyManager::CheckInited

**函数定义**

检查当前是否初始化过

**实现方法**

```c++
bool CheckInited();
```

**返回值**

bool值，false为未初始化，true为已初始化。



#### 2.4.2.20 VaultKeyManager::GetInstance

**函数定义**

获取唯一实例。

**实现方法**

```c++
static VaultKeyManager &GetInstance();
```

**返回值**

VaultKeyManager。



#### 2.4.2.21 VaultKeyManager::BorrowInstance

**函数定义**

获取KeyManager实例的指针。

**实现方法**

```c++
static VaultKeyManager *BorrowInstance();
```

**返回值**

VaultKeyManager*



#### 2.4.2.22 VaultKeyManager::GetLatestKey

**函数定义**

获取密钥。

**实现方法**

```c++
std::vector<std::byte> GetLatestKey(uint32_t domainId, uint32_t &keyId);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                           |
| ---------- | ------------ | ------------ | ---------------------------------- |
| domainId   | [IN]         | 是           | 作用域ID，取值为[0, domainCount)。 |
| keyId      | [OUT]        | 否           | 成功时为密钥id                     |

**返回值**

domainId的最后一个密钥，错误时为空。



### 2.4.3 基于 PSK 的密钥管理

组件不支持进程并发，进程安全由调用方保证。

加解密组件部署的属主需要与调用者保持一致，不允许多个服务共享一个组件。

#### 2.4.3.1 PskManager::Init

**函数定义**

PSK凭证管理初始化，调用KeyManager初始化函数进行初始化，默认使用OPENBAO。

**实现方法**

```c++
PskManagerRC Init(const PsKManagerInitOptions &opt);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                              |
| ---------- | ------------ | ------------ | ----------------------------------------------------- |
| opt        | [IN]         | 是           | 初始化配置，PsKManagerInitOptions定义请参见对应章节。 |

**返回值**

PskManagerRC退出码，成功返回PskManagerRC::OK，否则返回其它。PskManagerRC请参见对应章节。



#### 2.4.3.2 PskManager::UnInit

**函数定义**

PSK凭证管理去初始化，去初始化会去初始化KeyManager并且会清除内存中PSK凭证数据。

**实现方法**

```c++
PskManagerRC UnInit();
```

**返回值**

PskManagerRC退出码，成功返回PskManagerRC::OK，否则返回其它。PskManagerRC请参见对应章节。

**注意**

如果之前已经初始化KeyManager，那么调用PskManager::Init不会重复初始化KeyManager，此时调用PskManager::UnInit会去初始化用户之前的KeyManager，需要重新初始化。



#### 2.4.3.3 PskManager::GeneratePsk

**函数定义**

通过提供的PSK参数生成新的PSK凭证。

**实现方法**

```c++
PskManagerRC GeneratePsk(const PskParam &pskParam, Psk &psk);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                              |
| ---------- | ------------ | ------------ | ------------------------------------- |
| pskParam   | [IN]         | 是           | PSK生成参数，PskParam请参见对应章节。 |
| psk        | [OUT]        | 是           | 生成的PSK对象，Psk请参见对应章节。    |

**返回值**

PskManagerRC退出码，成功返回PskManagerRC::OK，否则返回其它。PskManagerRC请参见对应章节。



#### 2.4.3.4 PskManager::ImportPsk

**函数定义**

通过提供的PSK参数和PSK字符串生成新的PSK凭证。

**实现方法**

```c++
PskManagerRC ImportPsk(const PskParam &pskParam, const std::vector<uint8_t> &pskContent, Psk &psk);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                              |
| ---------- | ------------ | ------------ | ------------------------------------- |
| pskParam   | [IN]         | 是           | PSK生成参数，PskParam请参见对应章节。 |
| pskContent | [IN]         | 是           | PSK凭证                               |
| psk        | [OUT]        | 是           | 生成的PSK对象，Psk请参见对应章节。    |

**返回值**

PskManagerRC退出码，成功返回PskManagerRC::OK，否则返回其它。PskManagerRC请参见对应章节。



#### 2.4.3.5 PskManager::UpdatePsk

**函数定义**

通过提供的PSK id或PSK凭证字符串更新对应的PSK。

**实现方法**

```c++
PskManagerRC UpdatePsk(const uint32_t pskId, std::vector<uint8_t> pskContent, Psk &psk);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                     |
| ---------- | ------------ | ------------ | ------------------------------------------------------------ |
| pskId      | [IN]         | 是           | PSK凭证id，范围满足uint32_t要求，与pskContent必须有一个为有效值 |
| pskContent | [IN]         | 是           | 要更新的PSK凭证字符串，长度应，与pskId必须有一个为有效值     |
| psk        | [OUT]        | 是           | 更新后的PSK对象，Psk请参见对应章节。                         |

**返回值**

PskManagerRC退出码，成功返回PskManagerRC::OK，否则返回其它。PskManagerRC请参见对应章节。



#### 2.4.3.6 PskManager::DeletePsk

**函数定义**

通过提供的PSK id删除对应的PSK凭证。

**实现方法**

```c++
PskManagerRC DeletePsk(const uint32_t pskId);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**  |
| ---------- | ------------ | ------------ | --------- |
| pskId      | [IN]         | 是           | PSK凭证id |

**返回值**

PskManagerRC退出码，成功返回PskManagerRC::OK，否则返回其它。PskManagerRC请参见对应章节。



#### 2.4.3.7 PskManager::GetPsk

**函数定义**

通过提供的PSK id获取对应的PSK凭证。

**实现方法**

```c++
PskManagerRC GetPsk(const uint32_t pskId, std::vector<uint8_t> &pskContent);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**  |
| ---------- | ------------ | ------------ | --------- |
| pskId      | [IN]         | 是           | PSK凭证id |
| pskContent | [OUT]        | 是           | PSK凭证   |

**返回值**

PskManagerRC退出码，成功返回PskManagerRC::OK，否则返回其它。PskManagerRC请参见对应章节。



#### 2.4.3.8 PskManager::GetPskMetaData

**函数定义**

通过提供的PSK id获取对应的PSK凭证Meta信息。

**实现方法**

```c++
PskManagerRC GetPskMetaData(const uint32_t pskId, PskMetaData &pskMetaData);
```

**参数说明**

| **参数名**  | **参数类型** | **是否必选** | **描述**                                     |
| ----------- | ------------ | ------------ | -------------------------------------------- |
| pskId       | [IN]         | 是           | PSK凭证id                                    |
| pskMetaData | [OUT]        | 是           | PSK凭证meta信息，PskMetaData请参见对应章节。 |

**返回值**

PskManagerRC退出码，成功返回PskManagerRC::OK，否则返回其它。PskManagerRC请参见对应章节。



#### 2.4.3.9 PskManager::CheckPskValid

**函数定义**

通过提供的PSK id检查对应的PSK凭证是否有效。

**实现方法**

```c++
PskManagerRC CheckPskValid(const uint32_t pskId);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**  |
| ---------- | ------------ | ------------ | --------- |
| pskId      | [IN]         | 是           | PSK凭证id |

**返回值**

PskManagerRC退出码，成功返回PskManagerRC::OK，否则返回其它。PskManagerRC请参见对应章节。



#### 2.4.3.10 PskManager::CheckPskValidAndAutoUpdate

**函数定义**

通过提供的PSK id检查对应的PSK凭证是否有效，若失效则自动更新。

**实现方法**

```c++
PskManagerRC CheckPskValidAndAutoUpdate(const uint32_t pskId);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**  |
| ---------- | ------------ | ------------ | --------- |
| pskId      | [IN]         | 是           | PSK凭证id |

**返回值**

PskManagerRC退出码，成功返回PskManagerRC::OK，否则返回其它。PskManagerRC请参见对应章节。



#### 2.4.3.11 PskManager::LoadAllPsk

**函数定义**

从存储将加密的PSK凭证数据加载到组件，加载后清除内存中PSK，加载后的新PSK中pskId会重新按照pskList序列按照1，2，...重新排列。

**实现方法**

```c++
PskManagerRC LoadAllPsk(const std::vector<std::string_view pskCiphertext> &pskList);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**        |
| ---------- | ------------ | ------------ | --------------- |
| pskList    | [IN]         | 是           | PSK凭证密文数组 |

**返回值**

PskManagerRC退出码，成功返回PskManagerRC::OK，否则返回其它。PskManagerRC请参见对应章节。



### 2.4.4 通用密钥管理

#### 2.4.4.1 BorrowKeyManager

借用全局唯一的密钥管理实例指针（注意：请不要手动释放该指针，此处仅为借用）。

**实现方法**

```c++
KeyManager* KeyManagerFactory::BorrowKeyManager(KeyManagerTy type);
```

**返回值**

KeyManager* 返回对应密钥管理器类型的全局密钥管理实例指针

#### 2.4.4.2 KeyManagerFactory::Borrow

借用全局唯一的密钥管理实例指针（注意：请不要手动释放该指针，此处仅为借用）。

**实现方法**

```c++
static KeyManager *Borrow(KeyManagerTy type);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                         |
| ---------- | ------------ | ------------ | ------------------------------------------------ |
| type       | [IN]         | 是           | 请求的的密钥管理类型，请参见4.1.1.8 KeyManagerTy |

**返回值**

KeyManager* 返回对应密钥管理器类型的全局密钥管理实例指针



#### 2.4.4.3 KeyManager::Init

使用默认配置初始化密钥管理。

**实现方法**

```c++
KeyManagerRC Init(std::string_view exePath, std::string_view accessToken, uint32_t domainCount); 
```

**参数说明**

| **参数名**  | **参数类型** | **是否必选** | **描述**                     |
| ----------- | ------------ | ------------ | ---------------------------- |
| domainCount | [IN]         | 是           | 应用域数量，在（1,1024）之间 |
| exePath     | [IN]         | 是           | 执行的二进制路径             |
| accessToken | [IN]         | 是           | openbao/vault生成的token     |

**返回值**

KeyManagerRC请参见对应章节。



#### 2.4.4.4 KeyManager::Type

**函数定义**

返回当前 KeyManager 类型。

**实现方法**

```c++
KeyManagerTy Type();
```

**返回值**

KeyManagerTy类型，请参见对应章节。



#### 2.4.4.5 KeyManager::DomainCount

**函数定义**

返回当前 KeyManager 所支持的 最大 domain count。

**实现方法**

```c++
uint32_t DomainCount();
```

**返回值**

uint32_t domainCount，作用域的数量。



#### 2.4.4.6 KeyManager::CheckInited

**函数定义**

检查当前是否初始化过

**实现方法**

```c++
bool CheckInited();
```

**返回值**

bool值，false为未初始化，true为已初始化。



#### 2.4.4.7 KeyManager::UnInit

**函数定义**

反初始化密钥管理。

**实现方法**

```c++
KeyManagerRC UnInit();
```

**返回值**

KeyManagerRC请参见对应章节。



#### 2.4.4.8 KeyManager::CreateKey

**函数定义**

创建密钥。

**实现方法**

```c++
static std::pair<KeyManagerRC, uint32_t> CreateKey(uint32_t domainId);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述** |
| ---------- | ------------ | ------------ | -------- |
| domainId   | [IN]         | 是           | 作用域ID |

**返回值**

KeyManagerRC错误码，请参见对应章节。

uint32_t密钥ID，若创建密钥失败，返回0。



#### 2.4.4.9 KeyManager::RemoveKey

**函数定义**

删除密钥。

**实现方法**

KeyManagerRC RemoveKey(uint32_t domainId, uint32_t keyId);

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述** |
| ---------- | ------------ | ------------ | -------- |
| domainId   | [IN]         | 是           | 作用域ID |
| keyId      | [IN]         | 是           | 密钥ID   |

**返回值**

KeyManagerRC请参见对应章节。



#### 2.4.4.10 KeyManager::CheckDomainKeysExpired

**函数定义**

检查domain key是否过期。

**实现方法**

```c++
KeyManagerRC CheckDomainKeysExpired(uint32_t domainId, uint32_t lead);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**   |
| ---------- | ------------ | ------------ | ---------- |
| domainId   | [IN]         | 是           | 作用域ID   |
| lead       | [IN]         | 是           | 提前时间量 |

**返回值**

KeyManagerRC请参见对应章节。



#### 2.4.4.11 KeyManager::CheckDomainKeysExpiredAndAutoUpdate

**函数定义**

检查domain key是否过期，若过期则自动更新。

**实现方法**

```c++
KeyManagerRC CheckDomainKeysExpiredAndAutoUpdate(uint32_t domainId, uint32_t lead);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**     |
| ---------- | ------------ | ------------ | ------------ |
| domainId   | [IN]         | 是           | 作用域ID。   |
| lead       | [IN]         | 是           | 提前时间量。 |

**返回值**

KeyManagerRC请参见对应章节。



#### 2.4.4.12 KeyManager::DisplayKey

**函数定义**

展示密钥。

**实现方法**

KeyManagerRC DisplayKey(uint32_t domainId);

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**   |
| ---------- | ------------ | ------------ | ---------- |
| domainId   | [IN]         | 是           | 作用域ID。 |

**返回值**

KeyManagerRC请参见对应章节。



#### 2.4.4.13 KeyManager::DisplayAllKey

**函数定义**

展示所有密钥。

**实现方法**

```c++
KeyManagerRC DisplayAllKey();
```

**返回值**

KeyManagerRC请参见对应章节。



## 2.5 安全随机数

### 2.5.1 RandInit

**函数定义**

获取随机数接口初始化，全局初始化一次即可。若未显式调用该接口，首次调用 GetRand 时会使用默认配置自动初始化。
模块已初始化时，RandInit(config) 直接返回 CCSEC_CRYPT_OK，不会切换已有配置；如需更换配置，请先调用 RandDeinit()。

**实现方法**

```c++
CcsecCryptErrorCode RandInit(const RandConfig &config = RandConfig{});
```

**参数说明**

| **名称** | 参数类型 | **说明** |
| -------- | -------- | -------- |
| config | [IN] | 随机数模块配置。初始化成功后，drbgType、seedSource、securityStrength、predictionResistance、healthCheckInterval 会影响私有 EVP_RAND 实例的创建或生成行为；若模块已初始化，再次调用 RandInit(config) 直接返回成功，不会切换已有配置，需先调用 RandDeinit() 后重新初始化。HARDWARE 使用 JITTER parent，CUSTOM 使用指定 provider 获取 SEED-SRC parent。FIPS 模式使用 fips=yes 属性约束获取 DRBG；非 CUSTOM 熵源在 FIPS 模式下使用带 fips=yes 属性约束的 JITTER parent。seedSource="OS" 不是独立 parent，非 FIPS 模式下仍使用 SEED-SRC parent，并在 DRBG 实例化前调用 RAND_poll() 触发 OpenSSL OS 熵源补充采集。 |

**RandConfig 字段说明**

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| drbgType | string | "CTR-DRBG" | DRBG 算法类型，可选 "CTR-DRBG"、"HASH-DRBG"、"HMAC-DRBG"。 |
| seedSource | string | "SEED-SRC" | 熵源类型，可选 "SEED-SRC"、"OS"、"HARDWARE"、"CUSTOM"；"SEED-SRC" 使用 OpenSSL SEED-SRC parent；"OS" 在非 FIPS 模式下同样使用 SEED-SRC parent，并额外调用 RAND_poll() 触发 OS 熵源补充采集；"HARDWARE" 使用 OpenSSL JITTER RAND 作为 parent；"CUSTOM" 使用 customSeedProvider 指定 provider 中的 SEED-SRC parent。 |
| fipsMode | bool | false | FIPS 模式开关；启用后先加载 FIPS Provider，并用 fips=yes 属性约束获取 DRBG；seedSource!="CUSTOM" 时 parent 使用带 fips=yes 属性约束的 JITTER。是否可用取决于运行环境是否安装并启用对应 Provider/RAND 实现。 |
| customSeedProvider | string | "" | 自定义熵源 provider 名称，仅当 seedSource="CUSTOM" 时生效；为空时初始化失败；非 CUSTOM 熵源下该字段不参与 parent 选择。 |
| securityStrength | uint32_t | 256 | 安全强度，范围 [112,256]；CTR-DRBG 仅支持 128/192/256；HASH-DRBG/HMAC-DRBG 支持 [112,256]，并按区间选择满足强度的摘要算法。 |
| predictionResistance | bool | false | 预测抵抗；启用后每次生成前重取种。 |
| healthCheckInterval | uint32_t | 0 | 健康检查间隔(ms)，0 表示禁用。 |

**返回值**

失败返回错误码 成功返回 CCSEC_CRYPT_OK，请参见对应章节。



### 2.5.2 GetRand

**函数定义**

获取随机数。支持自动初始化；若随机数模块尚未初始化，接口会使用默认 RandConfig 自动初始化。

**实现方法**

```c++
CcsecCryptErrorCode GetRand(uint8_t *randBuff, const uint32_t randDataLength);
```

**参数说明**

| **名称**       | 参数类型 | **说明**                    |
| -------------- | -------- | --------------------------- |
| randBuff       | [OUT]    | 随机数指针。                |
| randDataLength | [IN]     | 随机数长度，范围(0,65536]。 |

**返回值**

失败返回错误码 成功返回 CCSEC_CRYPT_OK。



### 2.5.3 RandDeinit

**函数定义**

获取随机数接口去初始化，全局去初始化一次即可。

**实现方法**

```c++
void RandDeinit(void);
```

**返回值**

无。



### 2.5.4 GetSecurePwd

**函数定义**

获取安全密码口令

**实现方法**

```c++
CcsecCryptErrorCode GetSecurePwd(uint8_t *pwdBuff, const uint32_t pwdLength,
                                 const uint32_t retryTimes = DEFAULT_SECURE_PWD_RETRY_TIMES);
```

参数说明

| **名称**  | 参数类型 | **说明**                                                     |
| --------- | -------- | ------------------------------------------------------------ |
| pwdBuff   | [OUT]    | 安全密码口令指针。申请内存长度应大于等于pwdLength。  说明  生成口令包含如下至少两种字符的组合：  l   至少一个小写字母；  l   至少一个大写字母；  l   至少一个数字；  l   至少一个特殊字符：`~!@#$%^&*()-_=+\\ |
| pwdLength | [IN]     | 安全密码口令长度，范围: [8, 32]。                            |
| retryTimes | [IN] | 重试次数，默认 `DEFAULT_SECURE_PWD_RETRY_TIMES`（10次）。未传入时保持原有行为；传入正数时使用指定次数；0为非法参数。 |

**返回值**

失败返回错误码 成功返回 CCSEC_CRYPT_OK。



### 2.5.5 GetRandHealthStatus

**函数定义**

获取随机数生成器健康状态，包括健康标志、熵充足性、错误计数等信息。错误详情通过日志记录。

**实现方法**

```c++
CcsecCryptErrorCode GetRandHealthStatus(RandHealthStatus &status);
```

**参数说明**

| **名称** | 参数类型 | **说明** |
| -------- | -------- | -------- |
| status | [OUT] | 健康状态结构体，包含 isHealthy（健康标志）、entropySufficient（熵充足性）、errorCount（错误计数）。 |

**返回值**

失败返回错误码 成功返回 CCSEC_CRYPT_OK。



## 2.6 日志相关

用户需要自行实现日志，日志落盘、过滤、老化机制等集成方自行适配，组件提供日志外部设置入口和内容。

### 2.6.1 Logger::Instance

**函数定义**

获取Logger类的单例。

**实现方法**

```c++
static Logger *Instance()
```

**参数说明**

void。

**返回值**

Logger *。



### 2.6.2 Logger::Log

**函数定义**

记录日志，根据当前的日志初始化情况。

**实现方法**

```c++
void Log(int level, const std::string &message);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**   |
| ---------- | ------------ | ------------ | ---------- |
| logLevel   | [IN]         | 是           | 日志级别。 |
| message    | [IN]         | 是           | 日志内容。 |

**返回值**

LogRc请参见对应章节。



### 2.6.3 Logger::SetExternalLogFunction

**函数定义**

设置自定义日志函数。

**实现方法**

```c++
bool SetExternalLogFunction(ExternalLogFunction func);
```

**参数说明**

| **参数名** | **参数类型** | **是否必选** | **描述**                                                     |
| ---------- | ------------ | ------------ | ------------------------------------------------------------ |
| func       | [IN]         | 是           | using ExternalLogFunction = void (*)(int level, const char *msg); |

**返回值**

bool。

# 3 命令行功能

## 3.1 crypto_tool

**概述**

该工具主要用于基于第三方密钥管理工具（Openbao, Vault）相关的密钥生成，展示，移除；命令入参说明如下表。

| 入参        | 含义                           |
| ----------- | ------------------------------ |
| domainId    | 作用域，范围：[0,  1022]。     |
| domainCount | 作用域数量，范围：[2,  1023]。 |
| keyId       | 密钥管理使用的keyId。          |

二进制工具crypto_tool在rpm包安装后，默认路径为 /usr/bin/cdf/bin，配置文件路径为 /usr/bin/cdf/config。

使用 crypto_tool 工具前，请确保当前 crypto_tool 二进制的相对路径 ../config 存在并且有读写权限，该目录为读取 crypto_tool_config.json 配置的路径。

在使用 openbao/vault 前，请参考使用指南安装配置 Vault/OpenBao（可选） 完成相应配置。并且在调用 openbao/vault 功能时，crypto_tool 会要求输入相应的合法 access token，用户须提供。

### 1.1.1 配置文件 crypto_tool_config.json

目前 crypto_tool 要求用户提供配置文件，配置文件样例如下：

```json
{ 
   "algorithm": "AES256_GCM", # 用户指定的加密算法 
   "keyManagerType": "openbao", # 用户指定的密钥管理工具类型 
   "thirdKeyManager": { 
     "keyManagerPath": "/usr/bin/bao", # 用户指定的 openbao 可运行程序地址 
     "keyManagerAddr": "http://127.0.0.1:8200" # 用户指定的 openbao 端口地址 
   }， 
   "logConfig": { 
      "level":"info", 
      "path":"", 
      "rotationFileSize":20, 
      "rotationFileCount":20 
   } 
 }
```

| 入参                           | 含义                                                         | 合法值范围                                                   |
| ------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| algorithm                      | 加解密使用的密钥算法（注：并不是所有 keyManagerType 都对算法提供了完整支持） | openbao/vault支持 AES256_GCM,CHACHA20_POLY1305               |
| keyManagerType                 | 用户指定的密钥管理工具类型                                   | openbao,  vault                                              |
| thirdKeyManager.keyManagerPath | 用户指定的  openbao/vault 可运行程序地址（注：非法地址会导致运行失败） | 任意类型字符串                                               |
| thirdKeyManager.keyManagerAddr | 用户指定的  openbao/vault 端口地址  （注：非法地址会导致运行失败） | 任意类型字符串                                               |
| level                          | 日志级别                                                     | 包含trace,  debug, info, warn, error, critical。默认info。   |
| path                           | 日志路径                                                     | 日志路径 nullptr不输出到文件。  输出到文件时需要传入带文件名的路径且路径需存在，需是绝对路径。  默认nullptr |
| rotationFileSize               | 单个日志文件大小                                             | 单个日志文件大小 单位字节MB  默认 20。  取值范围为[1,  500]。  path不为null时生效 |
| rotationFileCount              | 日志保存数量                                                 | 日志保存数量，超过该数量后，最早的日志文件将被删除  默认 20  取值范围为 [1,  64]。  path不为null时生效 |

### 1.1.2 加密 encrypt

**命令格式**

```shell
./crypto_tool --encrypt domainId domainCount
```

**作用**

对文本进行加密。

**命令参考**

1. 执行以下命令对文本进行加密。

```shell
./crypto_tool --encrypt 0 2
```

2. 提示以下信息，输入密码，按Enter键确认。

```shell
please input the password to encrypt
```

3. 提示以下信息，再次输入密码，按Enter键确认。

```shell
please input the password to encrypt again
```

### 1.1.3 创建密钥 createkey

**命令格式**

```shell
./crypto_tool --createkey domainId domainCount
```

**作用**

在指定domainId domainCount下生成新的key。

**命令参考**

1. 执行以下命令创建密钥。

```shell
./crypto_tool --createkey 0 2
```

### 1.1.4 展示密钥 displaykey

**命令格式**

```
./crypto_tool --displaykey domainId domainCount
```

**作用**

展示domainId domainCount下的key。

**命令参考**

执行以下命令展示domainId domainCount下的key。

```shell
./crypto_tool --displaykey 0 2
```

### 1.1.5 删除密钥 removekey

**命令格式**

```shell
./crypto_tool --removekey domainId domainCount keyId
```

**作用**

移除domainId domainCount下指定的key。

**命令参考**

1. 执行以下命令。

```shell
./crypto_tool --removekey 0 2 0
```

### 1.1.6 重加密 reEncrypt

**命令格式**

```shell
./crypto_tool --reEncrypt domainId domainCount
```

**作用**

对已加密的文本进行重新加密，入参需是**--encrypt**命令生成的密文。

**命令参考**

1. 执行以下命令对已加密的文本进行重新加密。

```shell
./crypto_tool --reEncrypt 0 2
```

2. 提示以下信息，输入**--encrypt**命令生成的密文，按Enter键确认。

```shell
please input the password to encrypt
```

3. 提示以下信息，再次输入**--encrypt**命令生成的密文，按Enter键确认。

```shell
please input the password to encrypt again
```
