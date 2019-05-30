package com.github.qq275860560.service;

import java.util.Set;

/**
 * @author jiangyuanlin@163.com
 *
 */

public abstract class OauthService {

	/**根据客户端ID查询密码
	 * 在登录阶段时，要调用此接口获取到客户端密码，之后跟加密后的登录密码比较
	 * 根据客户端ID查询密码，此密码非明文密码，而是PasswordEncoder对明文加密后的密码，因为
	 * spring security框架中数据库默认保存的是PasswordEncoder对明文加密后的密码
	 * 客户端发送的密码加密后会跟这个函数返回的密码相匹配，如果成功，则认证成功，并保存到session中，
	 * 对于oauth2的密码模式和认证码模式程序任何地方可以通过以下代码获取当前的用户名称
	* String username=(String)SecurityContextHolder.getContext().getAuthentication().getName(); 
	* 对于oauth2的客户端模式程序任何地方可以通过以下代码获取当前的客户端id和资源所有者名称(客户端模式的资源所有者为空)
	* OAuth2Authentication oAuth2Authentication =  (OAuth2Authentication)SecurityContextHolder.getContext().getAuthentication();
	* String username= oAuth2Authentication.getUserAuthentication()==null?null:oAuth2Authentication.getUserAuthentication().getName();
	* String clientId=oAuth2Authentication.getOAuth2Request().getClientId(); 
	* log.info("资源用户名称=" + username+",客户端id="+clientId);  
	 * 再根据客户端id和资源所有者名称查询数据库获得其他信息
	 * @param clientId 客户端ID
	 * @return 返回加密后的客户端密码字符串
	 */
	public String getSecretByClientId(String clientId) {
		// 从缓存或数据库中查找
		return null;
	}

	/**根据客户端id查询认证码接收地址集合
	  * 在认证码模式中，当用户同意发送授权码时，需要把认证码告知客户端，此时客户端必须提供一个支持get请求的url作为回调地址
	  * 回调地址不要带任何参数,也不要带问号，授权服务器会直接在url后面追加?code=XXX参数进行发送
	 * 回调地址通常只有一个，但也支持多个，但只有跟用户同意授权的那个才能接受到认证码
	  * 如果系统不需要认证码模式，则不需要重写此接口
	 * @param clientId 客户端ID
	 * @return 回调地址集合
	 */
	public Set<String> getRegisteredRedirectUriByClientId(String clientId) {
		// 从缓存或数据库中查找
		return null;

	}

	/**根据客户端id查询SCOPE集合
	 * 在客户端访问系统时，需要对uri进行校验，
	 * 当客户端的SCOPE包含uri的所有SCOPE时，才能访问成功
	 * 客户端的SCOPE不需要前缀SCOPE_
	 * @param clientId 客户端ID
	 * @return SCOPE集合
	 */
	public Set<String> getScopesByClientId(String clientId) {//不要SCOPE_开头，前端传过来也不要SCOPE_开头
		// 从缓存或数据库中查找
		return null;
	}

	/**根据客户端id查询自动同意SCOPE集合
	 * 在认证码模式中，当用户申请授权码时，授权系统会把客户端的申请的所有SCOPE告知用户，如果某一个SCOPE设置为自动同意，则不会告知
	 *  客户端的SCOPE不需要前缀SCOPE_
	 * @param clientId 客户端ID
	 * @return SCOPE集合
	 */
	public Set<String> getAutoApproveScopesByClientId(String clientId) {//不要SCOPE_开头，前端传过来也不要SCOPE_开头
		// 从缓存或数据库中查找
		return null;
	}
	
	/**根据请求路径查询对应的SCOPE名称集合
	 * 在客户端访问系统时，需要对uri进行校验，
	 * 当客户端的SCOPE包含uri的所有SCOPE时，才能访问成功
	 * 客户端的SCOPE需要前缀SCOPE_
	 * @param clientId 客户端ID
	 * @return SCOPE集合
	 */
	public Set<String> getScopesByUrI(String url) {//SCOPE_开头
		// 从缓存或数据库中查找
		return null;
	}
 
	/**token的过期时间(单位为秒)
	 * @return
	 */
	public int getAccessTokenValiditySeconds() {
		return 10*365*24*3600;	 
	}
}
