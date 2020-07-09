package com.github.qq275860560.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import com.github.qq275860560.service.SecurityService;

import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableAuthorizationServer
@Slf4j
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.withClientDetails(new ClientDetailsService() {

			@Autowired
			private SecurityService securityService;

			@Override
			public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
				log.debug("登录或认证:获取客户端对应的SCOPE");
				return securityService.getClientDetailsByClientId(clientId);
			}

		});
	}

	@Autowired
	private UserDetailsService userDetailsService;
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	public JwtAccessTokenConverter jwtAccessTokenConverter;
	@Autowired
	public JwtTokenStore jwtTokenStore;

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
		endpoints.allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
		endpoints.reuseRefreshTokens(true);
		endpoints.userDetailsService(userDetailsService);
		endpoints.authenticationManager(authenticationManager);

		endpoints.accessTokenConverter(jwtAccessTokenConverter);
		endpoints.tokenStore(jwtTokenStore);
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
		oauthServer.allowFormAuthenticationForClients();// /oauth/confirm_access中有client_id和client_secret的会走ClientCredentialsTokenEndpointFilter
		oauthServer.tokenKeyAccess("permitAll()"); // url:/oauth/token_key,exposes public key for token verification if
													// using JWT tokens
		// oauthServer.checkTokenAccess("isAuthenticated()"); // url:/oauth/check_token
		// allow check token,访问tokenkey时需要经过认证
		oauthServer.checkTokenAccess("permitAll()");
	}

}
