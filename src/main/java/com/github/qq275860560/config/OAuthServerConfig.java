package com.github.qq275860560.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import com.github.qq275860560.security.MyAuthorizationCodeServices;
import com.github.qq275860560.security.MyClientDetailsService;
import com.github.qq275860560.security.MyDefaultTokenServices;
import com.github.qq275860560.security.MyJwtAccessTokenConverter;
import com.github.qq275860560.security.MyJwtTokenStore;
import com.github.qq275860560.security.MyScopeAffirmativeBased;
import com.github.qq275860560.security.MyScopeFilterInvocationSecurityMetadataSource;
import com.github.qq275860560.security.MyUserDetailsService;

@Configuration
public class OAuthServerConfig {

	@Configuration
	@EnableResourceServer
	protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

		@Autowired
		private MyDefaultTokenServices myDefaultTokenServices;

		@Override
		public void configure(ResourceServerSecurityConfigurer resources) {
			resources.tokenServices(myDefaultTokenServices);
		}

		@Autowired
		private MyScopeFilterInvocationSecurityMetadataSource myScopeFilterInvocationSecurityMetadataSource;

		@Autowired
		private MyScopeAffirmativeBased myScopeAffirmativeBased;
		
		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.requestMatchers()				.antMatchers("/oauth2/**");
			http.authorizeRequests().antMatchers("/oauth2/**").authenticated();
			
			http.authorizeRequests().withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
				@Override
				public <O extends FilterSecurityInterceptor> O postProcess(O o) {
					o.setSecurityMetadataSource(myScopeFilterInvocationSecurityMetadataSource);
					o.setAccessDecisionManager(myScopeAffirmativeBased);
					return o;
				}
			});
		}

	}

	@Configuration
	@EnableAuthorizationServer
	protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

/**

//传统
token=`curl -i -X GET "http://localhost:8080/login?username=username1&password=password1" | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X POST "http://localhost:8080/api/github/qq275860560/user/pageUser?pageNum=1&pageSize=10" -H "Authorization:Bearer  $token" 

token=`curl -i -X GET "http://localhost:8080/login?username=admin&password=admin" | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X GET "http://localhost:8080/api/github/qq275860560/user/saveUser?username=username2" -H "Authorization:Bearer  $token" 

//oauth2客户端模式
token=`curl -i -X POST "http://client1:secret1@localhost:8080/oauth/token?grant_type=client_credentials"  | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X POST "http://localhost:8080/oauth2/github/qq275860560/client/getClient?access_token=$token"



//oauth2密码模式
token=`curl -i -X POST "http://client1:secret1@localhost:8080/oauth/token?grant_type=password&username=username1&password=password1"  | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X POST "http://localhost:8080/oauth2/github/qq275860560/client/getClient?access_token=$token"


//oauth2认证码模式   
token=`curl -i -X GET "http://localhost:8080/login?username=username1&password=password1" | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token  
code=`curl -i -X GET "http://localhost:8080/oauth/authorize?client_id=client1&response_type=code"  -H "Authorization:Bearer  $token"  | grep Location | cut -d'=' -f2` 
echo 当前认证码为$code
token=`curl -i -X POST "http://localhost:8080/oauth/token?grant_type=authorization_code&client_id=client1&client_secret=secret1&scope=USER&code=$code"  | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X POST "http://localhost:8080/oauth2/github/qq275860560/client/getClient?access_token=$token"


//oauth2刷新token
token=`curl -i -X GET "http://localhost:8080/login?username=username1&password=password1" | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
code=`curl -i -X GET "http://localhost:8080/oauth/authorize?client_id=client1&response_type=code"  -H "Authorization:Bearer  $token"  | grep Location | cut -d'=' -f2` 
echo 当前认证码为$code
refresh_token=`curl -i -X POST "http://localhost:8080/oauth/token?grant_type=authorization_code&client_id=client1&client_secret=secret1&scope=USER&code=$code"  | grep refresh_token | awk -F "\"" '{print $12}'`
echo 当前refresh_token为$refresh_token
token=`curl -i -X POST "http://localhost:8080/oauth/token?grant_type=refresh_token&client_id=client1&client_secret=secret1&refresh_token=${refresh_token}"  | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X POST "http://localhost:8080/oauth2/github/qq275860560/client/getClient?access_token=$token"                    

//oauth2校验token
token=`curl -i -X POST "http://client1:secret1@localhost:8080/oauth/token?grant_type=client_credentials"  | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X POST  "http://client1:secret1@localhost:8080/oauth/check_token?token=$token"                   
            
 */

		@Autowired
		private MyClientDetailsService myClientDetailsService;

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients.withClientDetails(myClientDetailsService);
		}

		@Autowired
		private MyUserDetailsService myUserDetailsService;
		@Autowired
		private AuthenticationManager authenticationManager;
		@Autowired
		private MyAuthorizationCodeServices myAuthorizationCodeServices;

		@Autowired
		public MyJwtAccessTokenConverter myJwtAccessTokenConverter;
		@Autowired
		public MyJwtTokenStore myJwtTokenStore;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
			endpoints.allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
			endpoints.reuseRefreshTokens(true);
			endpoints.userDetailsService(myUserDetailsService);
			endpoints.authenticationManager(authenticationManager);
			endpoints.authorizationCodeServices(myAuthorizationCodeServices);
			endpoints.accessTokenConverter(myJwtAccessTokenConverter);
			endpoints.tokenStore(myJwtTokenStore);
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
			oauthServer.allowFormAuthenticationForClients();// /oauth/confirm_access中有client_id和client_secret的会走ClientCredentialsTokenEndpointFilter
			oauthServer.tokenKeyAccess("permitAll()"); // url:/oauth/token_key,exposes public key for token verification if using JWT tokens
			oauthServer.checkTokenAccess("isAuthenticated()"); // url:/oauth/check_token allow check token
		}
	}

}
