package com.github.qq275860560.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.qq275860560.security.MyAccessDeniedHandler;
import com.github.qq275860560.security.MyAuthenticationEntryPoint;
import com.github.qq275860560.security.MyAuthenticationFailureHandler;
import com.github.qq275860560.security.MyAuthenticationSuccessHandler;
import com.github.qq275860560.security.MyLogoutHandler;
import com.github.qq275860560.security.MyLogoutSuccessHandler;
import com.github.qq275860560.security.MyRequestHeaderAuthenticationFilter;
import com.github.qq275860560.security.MyRoleFilterInvocationSecurityMetadataSource;
import com.github.qq275860560.security.MyUserDetailsService;
import com.github.qq275860560.security.MyUsernamePasswordAuthenticationFilter;
import com.github.qq275860560.service.ClientService;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Configuration
@EnableWebSecurity
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private RestTemplate  restTemplate;
	@Autowired
	private ClientService  clientService;
	@Autowired
	private MyUserDetailsService myUserDetailsService;
	@Autowired
	private MyLogoutSuccessHandler myLogoutSuccessHandler;
	@Autowired
	private MyLogoutHandler myLogoutHandler;
	@Autowired
	private MyAccessDeniedHandler myAccessDeniedHandler;
	@Autowired
	private MyAuthenticationFailureHandler myAuthenticationFailureHandler;
	@Autowired
	private MyAuthenticationSuccessHandler myAuthenticationSuccessHandler;
	@Autowired
	private MyAuthenticationEntryPoint myAuthenticationEntryPoint;

	@Autowired
	private MyRoleFilterInvocationSecurityMetadataSource myRoleFilterInvocationSecurityMetadataSource;

 

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/**/*.html", "/**/*.css", "/**/*.woff", "/**/*.woff2", "/**/*.js", "/**/*.jpg",
				"/**/*.png", "/**/*.ico");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors();
		http.csrf().disable();
		// 解决不允许显示在iframe的问题
		http.headers().frameOptions().disable();
		// 禁用headers缓存
		http.headers().cacheControl();
		// 禁用session
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		
		http.addFilterBefore(new MyRequestHeaderAuthenticationFilter( authenticationManager(),
				 myUserDetailsService,  myAuthenticationEntryPoint, restTemplate,   clientService

				) ,
				UsernamePasswordAuthenticationFilter.class);
		http.addFilterBefore(new MyUsernamePasswordAuthenticationFilter(objectMapper,restTemplate,clientService),
				UsernamePasswordAuthenticationFilter.class);
		    
		http.requestMatchers().antMatchers( "/login", "/oauth/authorize", "/oauth/token", "/oauth/check_token",
				"/oauth/token_key", "/oauth/confirm_access", "/oauth/error");
			/*	
					http.authorizeRequests().antMatchers(  "/oauth/authorize", "/oauth/token", "/oauth/check_token",
							"/oauth/token_key", "/oauth/confirm_access", "/oauth/error").permitAll();
		  */
				 

				  //支持basic访问接口
				  //支持?access_token访问接口
	}

}