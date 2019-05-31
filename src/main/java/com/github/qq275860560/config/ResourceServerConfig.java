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
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

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
		http.requestMatchers().antMatchers("/oauth2/**");
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
