package com.github.qq275860560.config;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.util.Base64Utils;

import com.github.qq275860560.service.SecurityService;

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
	protected void configure(HttpSecurity http) throws Exception {
		http.cors();
		http.csrf().disable();
		http.headers().frameOptions().disable();
		http.formLogin().and().logout();
		http.authorizeRequests().antMatchers("/oauth/**").authenticated().anyRequest().permitAll();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder() {
			@Autowired
			private SecurityService securityService;

			@Override
			public String encode(CharSequence rawPassword) {
				return securityService.encode(rawPassword);
			}

			@Override
			public boolean matches(CharSequence rawPassword, String encodedPassword) {
				return securityService.matches(rawPassword, encodedPassword);
			}
		};
	}

	@Bean
	public UserDetailsService userDetailsService() {
		return new UserDetailsService() {
			@Autowired
			private SecurityService securityService;

			@Override
			public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
				log.debug("登录或认证:获取用户对应的角色权限");
				return securityService.getUserDetailsByUsername(username);
			}
		};
	}

	@Autowired
	private SecurityService securityService;

	@Bean
	public KeyPair getKeyPair() throws Exception {
		return new KeyPair(
				KeyFactory.getInstance("RSA")
						.generatePublic(new X509EncodedKeySpec(
								Base64Utils.decode(securityService.getPublicKeyBase64EncodeString().getBytes()))),
				KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(
						Base64Utils.decode(securityService.getPrivateKeyBase64EncodeString().getBytes()))));
	}

	@Bean
	public JwtAccessTokenConverter JwtAccessTokenConverter(KeyPair keyPair) {
		return new JwtAccessTokenConverter() {
			{
				setKeyPair(keyPair);
			}
		};
	}

	@Bean
	public JwtTokenStore JwtTokenStore(JwtAccessTokenConverter jwtAccessTokenConverter) {
		return new JwtTokenStore(jwtAccessTokenConverter);
	}
}