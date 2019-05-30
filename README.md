[TOC]
[认证中心服务器](https://github.com/qq275860560/authorization-server)调用示例



## 运行
命令行切换到项目根目录下，执行
```
mvn spring-boot:run
```

此时，本地会默认开启8080端口

## 测试
### 登录功能
执行命令

```
curl -i -X GET   "http://client1:secret1@localhost:8080/oauth/token_key"

```

### 登录成功响应结果

```
HTTP/1.1 200
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Thu, 30 May 2019 09:32:52 GMT

{"alg":"SHA256withRSA","value":"-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIaDCe9NzAAxU+C3+TFEA0IhuKs+8KgKyr8zIT3TpivBTNhlymOe0U5+L1yK7nWAu5JehXX7snnb79cF2IjJKg8CAwEAAQ==\n-----END PUBLIC KEY-----"}


```

其中value就是公钥，以后使用公钥即可验证用户提交的token，从token可以得知用户的角色列表




# 温馨提醒

* 此项目将会长期维护，增加或改进实用的功能
* 右上角点击star，给我继续前进的动力,谢谢