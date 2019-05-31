package com.github.qq275860560.service.impl;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import com.github.qq275860560.service.SecurityService;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Component
@Slf4j
public class SecurityServiceImpl extends SecurityService {

	

	private Map<String, Map<String,Object>> user_cache = new HashMap<String, Map<String,Object>>() {
		{
			put("username1", 					
					new HashMap<String,Object>(){{
						put("password",new BCryptPasswordEncoder().encode("123456"));
			            put("roleNames","ROLE_USER");//逗号分开
					}}
			);
			put("username2", 					
					new HashMap<String,Object>(){{
						put("password",new BCryptPasswordEncoder().encode("123456"));
			            put("roleNames","ROLE_ADMIN");	//逗号分开		         
					}}
			);
			put("admin", 					
					new HashMap<String,Object>(){{
						put("password",new BCryptPasswordEncoder().encode("123456"));
			            put("roleNames","ROLE_ADMIN,ROLE_USER");	//逗号分开		        
					}});
			
			
		}
	};

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
	
	@Override
	public UserDetails getUserDetailsByUsername(String username) {
		// 从缓存或数据库中查找
		Map<String, Object> map= user_cache.get(username) ;//查询数据库
		
		String password = (String)map.get("password");
		 
		boolean enabled = true;// 帐号是否可用
		boolean accountNonExpired = true;// 帐户是否过期
		boolean credentialsNonExpired = true;// 帐户密码是否过期，一般有的密码要求性高的系统会使用到，比较每隔一段时间就要求用户重置密码
		boolean accountNonLocked = true;// 帐户是否被冻结

		String roleNames = (String)map.get("roleNames");
		// 初始化用户的权限
		List<GrantedAuthority> grantedAuthorities = AuthorityUtils
				.commaSeparatedStringToAuthorityList(roleNames);
		// controller方法参数通过@AuthenticationPrincipal可以获得该对象
		return new org.springframework.security.core.userdetails.User(username, password, enabled, accountNonExpired,
				credentialsNonExpired, accountNonLocked, grantedAuthorities);

	}
	 
	
	private Map<String, Map<String, Object>> requestURI_cache = new HashMap<String, Map<String, Object>>() {
		{

			
			put("/api/github/qq275860560/user/**", new HashMap<String, Object>() {//请注意正则表达式的写法，是两个*号
				{
					put("roleNames", "ROLE_ADMIN");// 只需此角色即可访问
				}
			});
			put("/api/github/qq275860560/user/pageUser", new HashMap<String, Object>() {
				{
					put("roleNames", "ROLE_USER");// 只需此权限即可访问
				}
			});

			put("/api/github/qq275860560/user/listUser", new HashMap<String, Object>() {
				{
					put("roleNames", "ROLE_USER");// 只需此权限即可访问
				}
			});
			put("/api/github/qq275860560/user/getUser", new HashMap<String, Object>() {
				{
					put("roleNames", "ROLE_USER");// 只需此权限即可访问
				}
			});
			put("/api/github/qq275860560/user/saveUser", new HashMap<String, Object>() {
				{
					put("roleNames", "");
				}
			});
			put("/api/github/qq275860560/user/deleteUser", new HashMap<String, Object>() {
				{
					put("roleNames", "");
				}
			});
			put("/api/github/qq275860560/user/updateUser", new HashMap<String, Object>() {
				{
					put("roleNames", "");
				}
			});			

	 
			
			put("/api/github/qq275860560/client/**", new HashMap<String, Object>() {//请注意正则表达式的写法，是两个*号
				{
					put("scopes", "SCOPE_USER");// 至少要此权限才能访问,通常开放平台的接口才需要设置 这个属性
				}
			});
			put("/api/github/qq275860560/client/saveClient", new HashMap<String, Object>() {
				{
					put("scopes", "SCOPE_ADMIN");// 至少要此权限才能访问,通常开放平台的接口才需要设置 这个属性
				}
			});
			put("/api/github/qq275860560/client/getClient", new HashMap<String, Object>() {
				{
					put("scopes", "");// 至少要此权限才能访问,通常开放平台的接口才需要设置 这个属性
				}
			});
		}
	};

	/**
	 * 根据请求路径查询对应的角色名称集合
	 * 在授权阶段时，要调用此接口获取权限，之后跟登录用户的权限比较
	 * 登录用户至少拥有一个角色，才能访问
	 * 如果返回null或空集合或包含ROLE_ANONYMOUS，代表该url不需要权限控制，任何用户(包括匿名)用户都可以访问
	 * 如果url符合某个正则表达式，应当把正则表达式的角色也返回，比如/api/a的角色为ROLE_1,ROLE_2, 而数据库中还存在/api/**的角色为ROLE_3,ROLE_4；由于/api/a属于正则表达式/api/*,所以应当返回ROLE_1,ROLE_2,ROLE_3,ROLE_4
	 * @param requestURI 请求路径（ip端口之后的路径）
	 * @return 权限集合
	 */
	@Override
	public Set<String> getRoleNamesByRequestURI(String requestURI) {// ROLE_开头
		// 从缓存或数据库中查找
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		Set<String> set = new HashSet<>();
		for (String pattern : requestURI_cache.keySet()) {
			if (antPathMatcher.match(pattern, requestURI)) {
				Map<String, Object> map = (Map<String, Object>) requestURI_cache.get(pattern);
				if (map == null)
					continue;
				String attributesString = (String) map.get("roleNames");
				if (StringUtils.isEmpty(attributesString))
					continue;
				set.addAll(Arrays.asList(attributesString.split(",")));
			}
		}
		return set;
	}
 
	@Override
	public Set<String> getScopesByRequestURI(String requestURI) {//SCOPE_开头
		// 从缓存或数据库中查找
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		Set<String> set = new HashSet<>();
		for (String pattern : requestURI_cache.keySet()) {
			if (antPathMatcher.match(pattern, requestURI)) {
				Map<String, Object> map = (Map<String, Object>) requestURI_cache.get(pattern);
				if (map == null)
					continue;
				String attributesString = (String) map.get("scopes");
				if (StringUtils.isEmpty(attributesString))
					continue;
				set.addAll(Arrays.asList(attributesString.split(",")));
			}
		}
		return set;
	}
  
	private Map<String, Map<String,Object>> client_cache = new HashMap<String, Map<String,Object>>() {
		{
			put("client1", new HashMap<String,Object>() {
				{					
					put("secret",new BCryptPasswordEncoder().encode("123456"));
					put("registeredRedirectUris","http://localhost:8081/api/client1/getCode");
					put("authorizedGrantTypes","password,authorization_code,refresh_token,client_credentials");
					put("scopes","USER");//不需要前缀SCOPE_,//逗号分开
					put("autoApproveScopes","USER");//不需要前缀SCOPE_,//逗号分开
					put("accessTokenValiditySeconds",10*365*24*3600);
			 
				}
			});
			put("admin", new HashMap<String,Object>() {
				{
					put("secret",new BCryptPasswordEncoder().encode("123456"));
					put("registeredRedirectUris","http://localhost:8081/api/admin/getCode");
					put("authorizedGrantTypes","authorization_code,refresh_token,implicit,password,client_credentials");

					put("scopes","ADMIN,USER");//不需要前缀SCOPE_,//逗号分开
					put("autoApproveScopes","ADMIN,USER");//不需要前缀SCOPE_,//逗号分开
					put("accessTokenValiditySeconds",10*365*24*3600);
				}
			});
			
			put("gateway", new HashMap<String,Object>() {//网关只支持密码模式，不需要
				{
					put("secret",new BCryptPasswordEncoder().encode("123456"));
					put("registeredRedirectUris","http://localhost:8081/api/admin/getCode");
					put("authorizedGrantTypes","refresh_token,implicit,password,client_credentials");

					put("scopes","ADMIN,USER");//不需要前缀SCOPE_,//逗号分开
					put("autoApproveScopes","ADMIN,USER");//不需要前缀SCOPE_,//逗号分开
				
					put("accessTokenValiditySeconds",10*365*24*3600);
				}
			});
			
			 
		}
	};
	
 
	
	@Override
	public ClientDetails getClientDetailsByClientId(String clientId) {
		// 从缓存或数据库中查找
		Map<String, Object> map=client_cache.get(clientId);//查询数据库
		BaseClientDetails baseClientDetails = new BaseClientDetails();
		baseClientDetails.setClientId(clientId);
		baseClientDetails.setClientSecret((String)map.get("secret"));
		// 接收认证码的url
		Set<String> registeredRedirectUris = new HashSet<String>(Arrays.asList( ((String)map.get("registeredRedirectUris")).split(",")));
	 
			baseClientDetails.setRegisteredRedirectUri(registeredRedirectUris  );
		 
		Set<String>  authorizedGrantTypes = new HashSet<String>(Arrays.asList( ((String)map.get("authorizedGrantTypes")).split(",")));
	 
		baseClientDetails.setAuthorizedGrantTypes(
				authorizedGrantTypes);
		 
		// 客户端的权限
		Set<String> scopes= new HashSet<String>(Arrays.asList( ((String)map.get("scopes")).split(",")));
	 
			baseClientDetails.setScope(scopes);		
	 
		Set<String> autoApproveScopes=new HashSet<String>(Arrays.asList( ((String)map.get("autoApproveScopes")).split(",")));
	 
			baseClientDetails.setAutoApproveScopes(autoApproveScopes);
	 
		baseClientDetails.setAccessTokenValiditySeconds((Integer)map.get("accessTokenValiditySeconds")   );
	
		return baseClientDetails;
 
	}

	
	
	
	
	
	
	
	
	
	
	
	
	public Map<String, String> getClient() {
		return new HashMap<String, String>() {
			{
				put("client_id", "gateway");
				put("client_secret", "123456");
			}
		};
	}

	public String getAuthorizationServerUrl() {
		return "http://localhost:8080";
	}

	@Autowired
	private RestTemplate restTemplate;

	private RsaVerifier rsaVerifier;

	/**
	 * 获取认证授权服务器的公钥
	 * 默认第一次访问的时候，加载认证授权服务器的公钥,
	 * 如果应用本身也是认证服务器读取配置文件
	 * 如果认证授权逻辑不再该应用中，通过默认的/oauth/token_key加载公钥
	 * @return 公钥
	 */
	@Override
	public RsaVerifier getRsaVerifier() {

		if (rsaVerifier == null) {
			try {
				ResponseEntity<Map> result = restTemplate.exchange(getAuthorizationServerUrl() + "/oauth/token_key",

						HttpMethod.GET, new HttpEntity<>(new HttpHeaders() {
							{
								setBasicAuth(getClient().get("client_id"), getClient().get("client_secret"));
							}
						}), Map.class);
				String public_key = (String) result.getBody().get("value");
				public_key=public_key.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("\n-----END PUBLIC KEY-----", "");
				byte[] keyBytes = Base64Utils.decode(public_key.getBytes());
				X509EncodedKeySpec keySpec_publicKey = new X509EncodedKeySpec(keyBytes);
				KeyFactory keyFactory_publicKey = KeyFactory.getInstance("RSA");
				PublicKey publicKey = keyFactory_publicKey.generatePublic(keySpec_publicKey);

				rsaVerifier = new RsaVerifier((RSAPublicKey) publicKey);

			} catch (Exception e) {
				log.error("", e);
			}

		}

		return rsaVerifier;

	}
}
