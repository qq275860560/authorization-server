package com.github.qq275860560.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Configuration
@EnableWebSecurity
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

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
		http.formLogin().permitAll();
		http.requestMatchers().antMatchers("/login", "/oauth/authorize", "/oauth/token", "/oauth/check_token",
				"/oauth/token_key", "/oauth/confirm_access", "/oauth/error");

		http.authorizeRequests().antMatchers("/oauth/authorize", "/oauth/token", "/oauth/check_token",
				"/oauth/token_key", "/oauth/confirm_access", "/oauth/error").permitAll();

	}

	// todo 重启之后token和code失效问题

}