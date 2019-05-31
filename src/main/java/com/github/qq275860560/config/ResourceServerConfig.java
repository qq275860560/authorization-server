package com.github.qq275860560.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import com.github.qq275860560.security.MyDefaultTokenServices;
import com.github.qq275860560.security.MyRoleScopeConsensusBased;
import com.github.qq275860560.security.MyRoleScopeFilterInvocationSecurityMetadataSource;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

	@Autowired
	private MyDefaultTokenServices myDefaultTokenServices;

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) {
		resources.tokenServices(myDefaultTokenServices);
	}

	@Autowired
	private MyRoleScopeFilterInvocationSecurityMetadataSource myRoleScopeFilterInvocationSecurityMetadataSource;

	@Autowired
	private MyRoleScopeConsensusBased myRoleScopeConsensusBased;

	/**

	//传统
	token=`curl -i -X GET "http://localhost:8080/login?username=username1&password=123456" | grep access_token | awk -F "\"" '{print $4}'`
	echo 当前token为$token
	curl -i -X POST "http://localhost:8080/api/github/qq275860560/user/pageUser?pageNum=1&pageSize=10" -H "Authorization:Bearer  $token" 

	token=`curl -i -X GET "http://localhost:8080/login?username=admin&password=123456" | grep access_token | awk -F "\"" '{print $4}'`
	echo 当前token为$token
	curl -i -X GET "http://localhost:8080/api/github/qq275860560/user/saveUser?username=username2" -H "Authorization:Bearer  $token" 

	//oauth2客户端模式
	token=`curl -i -X POST "http://client1:123456@localhost:8080/oauth/token?grant_type=client_credentials"  | grep access_token | awk -F "\"" '{print $4}'`
	echo 当前token为$token
	curl -i -X POST "http://localhost:8080/oauth2/github/qq275860560/client/getClient?access_token=$token"



	//oauth2密码模式
	token=`curl -i -X POST "http://client1:123456@localhost:8080/oauth/token?grant_type=password&username=username1&password=123456"  | grep access_token | awk -F "\"" '{print $4}'`
	echo 当前token为$token
	curl -i -X POST "http://localhost:8080/oauth2/github/qq275860560/client/getClient?access_token=$token"

	token=`curl -i -X POST "http://client1:123456@localhost:8080/oauth/token?grant_type=password&username=username1&password=123456"  | grep access_token | awk -F "\"" '{print $4}'`
	echo 当前token为$token
	curl -i -X POST "http://localhost:8080/oauth2/github/qq275860560/client/pageClient?access_token=$token"

	//oauth2认证码模式   
	token=`curl -i -X GET "http://localhost:8080/login?username=username1&password=123456" | grep access_token | awk -F "\"" '{print $4}'`
	echo 当前token为$token  
	code=`curl -i -X GET "http://localhost:8080/oauth/authorize?client_id=client1&response_type=code"  -H "Authorization:Bearer  $token"  | grep Location | cut -d'=' -f2` 
	echo 当前认证码为$code
	token=`curl -i -X POST "http://localhost:8080/oauth/token?grant_type=authorization_code&client_id=client1&client_secret=123456&scope=USER&code=$code"  | grep access_token | awk -F "\"" '{print $4}'`
	echo 当前token为$token
	curl -i -X POST "http://localhost:8080/oauth2/github/qq275860560/client/getClient?access_token=$token"


	//oauth2刷新token
	token=`curl -i -X GET "http://localhost:8080/login?username=username1&password=123456" | grep access_token | awk -F "\"" '{print $4}'`
	echo 当前token为$token
	code=`curl -i -X GET "http://localhost:8080/oauth/authorize?client_id=client1&response_type=code"  -H "Authorization:Bearer  $token"  | grep Location | cut -d'=' -f2` 
	echo 当前认证码为$code
	refresh_token=`curl -i -X POST "http://localhost:8080/oauth/token?grant_type=authorization_code&client_id=client1&client_secret=123456&scope=USER&code=$code"  | grep refresh_token | awk -F "\"" '{print $12}'`
	echo 当前refresh_token为$refresh_token
	token=`curl -i -X POST "http://localhost:8080/oauth/token?grant_type=refresh_token&client_id=client1&client_secret=123456&refresh_token=${refresh_token}"  | grep access_token | awk -F "\"" '{print $4}'`
	echo 当前token为$token
	curl -i -X POST "http://localhost:8080/oauth2/github/qq275860560/client/getClient?access_token=$token"                    

	//oauth2校验token
	token=`curl -i -X POST "http://client1:123456@localhost:8080/oauth/token?grant_type=client_credentials"  | grep access_token | awk -F "\"" '{print $4}'`
	echo 当前token为$token
	curl -i -X POST  "http://client1:123456@localhost:8080/oauth/check_token?token=$token"                   
	            
	 */
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.requestMatchers().antMatchers("/oauth2/**");
		http.authorizeRequests().antMatchers("/oauth2/**").authenticated();

		http.authorizeRequests().withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
			@Override
			public <O extends FilterSecurityInterceptor> O postProcess(O o) {
				o.setSecurityMetadataSource(myRoleScopeFilterInvocationSecurityMetadataSource);
				o.setAccessDecisionManager(myRoleScopeConsensusBased);
				return o;
			}
		});
	}

}
