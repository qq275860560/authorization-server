package com.github.qq275860560.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
 
import com.github.qq275860560.security.MyClientDetailsService;
import com.github.qq275860560.security.MyJwtAccessTokenConverter;
import com.github.qq275860560.security.MyJwtTokenStore;
import com.github.qq275860560.security.MyUserDetailsService;

@Configuration
@EnableAuthorizationServer
public   class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {



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
		public MyJwtAccessTokenConverter myJwtAccessTokenConverter;
		@Autowired
		public MyJwtTokenStore myJwtTokenStore;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
			endpoints.allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
			endpoints.reuseRefreshTokens(true);
			endpoints.userDetailsService(myUserDetailsService);
			endpoints.authenticationManager(authenticationManager);
	 
			endpoints.accessTokenConverter(myJwtAccessTokenConverter);
			endpoints.tokenStore(myJwtTokenStore);
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
			oauthServer.allowFormAuthenticationForClients();// /oauth/confirm_access中有client_id和client_secret的会走ClientCredentialsTokenEndpointFilter
			oauthServer.tokenKeyAccess("permitAll()"); // url:/oauth/token_key,exposes public key for token verification if using JWT tokens
			//oauthServer.checkTokenAccess("isAuthenticated()"); // url:/oauth/check_token allow check token,访问tokenkey时需要经过认证
			oauthServer.checkTokenAccess("permitAll()");
		}
	 

}
