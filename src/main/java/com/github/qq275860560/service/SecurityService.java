package com.github.qq275860560.service;

import java.util.Collections;
import java.util.Set;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

/**
 * @author jiangyuanlin@163.com
 *
 */
public abstract class SecurityService {
	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	/**用户密码加密策略
	 *  用户注册阶段,用户的密码保存到数据库前通常要进行加密，此接口定义解密策略
	 *  传统使用md5进行加密入库容易猜解，比如所有人的123456进行md5后保存到数据库都是一样的，建议使用BCryptPasswordEncoder
	 *  如果使用spring默认的BCryptPasswordEncoder,不需要重写该方法
	 * @param rawPassword 用户登录时输入的明文密码
	 * @return 数据库中的密码
	 */
	public String encode(CharSequence rawPassword) {
		return passwordEncoder.encode(rawPassword);// spring推荐使用该方式加密
		//return org.springframework.util.DigestUtils.md5DigestAsHex(rawPassword.toString().getBytes());
	}

	

	/**用户密码匹配策略
	 *   用户登录阶段,需要校验密码准确性
	  *  如果使用spring默认的BCryptPasswordEncoder,不需要重写该方法
	 * @param rawPassword 用户登录时输入的明文密码
	 * @param encodedPassword 数据库中加密后的密码
	 * @return 如果匹配返回真，否则返回假
	 */
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		return passwordEncoder.matches(rawPassword, encodedPassword);// spring推荐使用该方式匹配
		//return org.springframework.util.DigestUtils.md5DigestAsHex(rawPassword.toString().getBytes()).equals(encodedPassword);
	}

	

	/** 登录用户密码
	 * 在登录阶段时，要调用此接口获取到用户密码，之后跟加密后的登录密码比较
	 * 根据登录账号查询密码，此密码非明文密码，而是PasswordEncoder对明文加密后的密码，因为
	 * spring security框架中数据库默认保存的是PasswordEncoder对明文加密后的密码
	 * 用户发送的密码加密后会跟这个函数返回的密码相匹配，如果成功，则认证成功，并保存到session中，程序任何地方可以通过以下代码获取当前的username
	 * String username=(String)SecurityContextHolder.getContext().getAuthentication().getName();  
	 * 再根据用户名称查询数据库获得其他个人信息

	 
	 * 登录用户 对应的角色名称集合
	 * 在认证阶段时，要调用此接口初始化用户权限
	 * 如果返回null或空集合，代表该用户没有权限，这类用户其实跟匿名用户没有什么区别
	 * 如果username隶属于某高层次的角色或组织，应当把高层次的角色或组织对应的角色也返回，比如username的角色为ROLE_1, ROLE_1继承ROLE_2角色，并且username属于A部门，A部门拥有角色ROLE_3；所以应当返回ROLE_1,ROLE_2,ROLE_3
 
	 */
	
	public UserDetails getUserDetailsByUsername(String username) {
		return null ;
	}


	/**
	 * 根据请求路径查询对应的角色名称集合
	 * 在授权阶段时，要调用此接口获取权限，之后跟登录用户的权限比较
	 * 登录用户至少拥有一个角色，才能访问
	 * 如果返回null或空集合或包含ROLE_ANONYMOUS，代表该url不需要权限控制，任何用户(包括匿名)用户都可以访问
	 * 如果url符合某个正则表达式，应当把正则表达式的角色也返回，比如/api/a的角色为ROLE_1,ROLE_2, 而数据库中还存在/api/*的角色为ROLE_3,ROLE_4；由于/api/a属于正则表达式/api/*,所以应当返回ROLE_1,ROLE_2,ROLE_3,ROLE_4
	 * @param requestURI 请求路径（ip端口之后的路径）
	 * @return 权限集合
	 */
	public Set<String> getRoleNamesByRequestURI(String requestURI){//ROLE_开头
		return Collections.EMPTY_SET;  // 数据库查出来的url角色权限，默认只要具有ROLE_ANONYMOUS角色的用户即可访问
	 
	}

	


	
	
	 

	/**私钥字符串(参考https://github.com/qq275860560/common/blob/master/src/main/java/com/github/qq275860560/common/util/RsaUtil.java)
	 * @return 私钥字符串
	 */
	public String getPrivateKeyBase64EncodeString() {
		return "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAhoMJ703MADFT4Lf5MUQDQiG4qz7wqArKvzMhPdOmK8FM2GXKY57RTn4vXIrudYC7kl6Fdfuyedvv1wXYiMkqDwIDAQABAkBq2uIjhmvOo2D8nWmKJ3tnJ56p+x/2fkw9w4JeuSnCi2vvfcUN4Sb2FRR5Ckgw+4DExvC8W5Fjr5EGg6MedjvxAiEA2O+6sjn3zvljzREYHc8Pc3dlmaSW2zmCo/nwyCO9EUUCIQCeu7n4oBtnv7K++8461grqlB1Afu5Es89k/XvES6DhQwIhANCO+PArpsBHJtmZm5Pc4z/hA76Ia7frPFulCQWAxl35AiEAlH9tQPKQEORfFZq+2X4q4j/EifT1dWJ+cK1Pn1ldXb8CIQDUD6VYAC/nR+nIYUiU12kn2uBKe1bg2fwnUOJotFc6Kw==";
	}

	/**公钥字符串(参考https://github.com/qq275860560/common/blob/master/src/main/java/com/github/qq275860560/common/util/RsaUtil.java)
	 * @return 公钥字符串 
	 */
	public String getPublicKeyBase64EncodeString(){
		return "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIaDCe9NzAAxU+C3+TFEA0IhuKs+8KgKyr8zIT3TpivBTNhlymOe0U5+L1yK7nWAu5JehXX7snnb79cF2IjJKg8CAwEAAQ==";
	}
	
	/**根据请求路径查询对应的SCOPE名称集合
	 * 在客户端访问系统时，需要对uri进行校验，
	 * 当客户端的SCOPE包含uri的所有SCOPE时，才能访问成功
	 * 客户端的SCOPE需要前缀SCOPE_
	 * @param requestURI 请求相对路径
	 * @return SCOPE集合
	 */
	public Set<String> getScopesByRequestURI(String requestURI) {//SCOPE_开头
		// 从缓存或数据库中查找
		return Collections.EMPTY_SET;
	}
	
	
	

	/**客户端密码
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
	 
	
	*认证码接收地址(回调地址)集合
	  * 在认证码模式中，当用户同意发送授权码时，需要把认证码告知客户端，此时客户端必须提供一个支持get请求的url作为回调地址
	  * 授权服务器会直接在 回调地址后面追加code=XXX参数进行重定向
	 * 回调地址通常只有一个，但也支持多个，但只有跟用户同意授权的那个认证码才有效
  	 
 
	
	*授权类型集合
	  * 通常网关（本应用客户端）支持客户端模式和密码模式,第三方客户端支持客户端模式和认证码模式
	 
	 

	*SCOPE集合
	 * 在客户端访问系统时，需要对uri进行权限校验，
	 * 当客户端的scopes包含资源对应的所有SCOPE时，访问资源才能成功
	 * 浏览器发送/oauth/authorize请求时scope参数值不需要前缀SCOPE_
	 
	

	*自动同意SCOPE集合
	 * 在认证码模式中，当用户申请授权码时，授权系统会把客户端的申请的所有SCOPE告知用户，如果某一个SCOPE设置为自动同意，则不会告知
	  
	 
	
 
	 * token的过期时间(单位为秒)
	 * @param clientId 客户端id
	 * @return 客户端属性 
	 */
	 
	public ClientDetails getClientDetailsByClientId(String clientId) {
		// 从缓存或数据库中查找
		return null;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	/**获取网关（客户端）的client_id和client_secret
	  *  一个应用通常服务器有3种，网关（客户端），资源服务器，认证授权服务器
	  *  登陆时，用户通过浏览器带上账号username密码password访问网关的/login，网关通过oauth2密码模式带上其client_id,client_secret和username,password向认证授权服务器请求发出请求/oauth/token，再把响应回来的access_token返回到浏览器
	  *  网关访问 "/oauth/check_token","/oauth/token_key", "/oauth/confirm_access", "/oauth/error"等接口也需要client_id和client_secret
	  *  所以网关需要一个client_id和client_secret
	  * 如果当前应用不是网关，可以忽略此接口
	 * @return 网关（客户端）的client_id和client_secret
	 */
	public ClientDetails getClientDetails() {
		BaseClientDetails baseClientDetails = new BaseClientDetails();
		baseClientDetails.setClientId("gateway");
		baseClientDetails.setClientSecret("123456");
		return baseClientDetails;
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