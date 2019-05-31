package com.github.qq275860560.service;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.jwt.crypto.sign.RsaVerifier;
/**
 * @author jiangyuanlin@163.com
 *
 */

public abstract class GatewayService {
	
	
	/**获取网关（客户端）的client_id和client_secret
	  *  一个应用通常服务器有3种，网关（客户端），资源服务器，认证授权服务器
	  *  登陆时，用户通过浏览器带上账号username密码password访问网关的/login，网关通过oauth2密码模式带上其client_id,client_secret和username,password向认证授权服务器请求发出请求/oauth/token，再把响应回来的access_token返回到浏览器
	  *  网关访问 "/oauth/check_token","/oauth/token_key", "/oauth/confirm_access", "/oauth/error"等接口也需要client_id和client_secret
	  *  所以网关需要一个client_id和client_secret
	  * 如果当前应用不是网关，可以忽略此接口
	 * @return 网关（客户端）的client_id和client_secret
	 */
	public Map<String,String> getClient() {	
		return new HashMap<String,String>() {{
			put("client_id","gateway");
			put("client_secret","123456");
		}};
	}
	 
	 
	/**获取认证授权服务器的url
	 *   网关访问 "/oauth/token","/oauth/check_token","/oauth/token_key", "/oauth/confirm_access", "/oauth/error"等接口需要知道认证授权服务器url前缀
	 *  如果当前应用不是网关，可以忽略此接口
	 * @return 认证授权服务器的url
	 */
	public String getAuthorizationServerUrl() {	 
		return  "http://localhost:8080";
	}
	
	
 
	/**
	 * 获取认证授权服务器的公钥
	 * 默认第一次访问的时候，加载认证授权服务器的公钥,
	 * 如果应用本身也是认证服务器读取配置文件
	 * 如果认证授权逻辑不再该应用中，通过默认的/oauth/token_key加载公钥
	 * @return 公钥
	 */
	public RsaVerifier getRsaVerifier() {
		 return null;
	}
}
