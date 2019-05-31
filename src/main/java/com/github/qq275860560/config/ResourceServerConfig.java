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

	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.requestMatchers().antMatchers("/api/**");
		http.authorizeRequests().antMatchers("/api/**").authenticated();

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
