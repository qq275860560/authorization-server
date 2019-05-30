package com.github.qq275860560.security;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.github.qq275860560.service.OauthService;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Service
@Slf4j
public class MyClientDetailsService implements ClientDetailsService {

	@Autowired
	private OauthService oauthService;

	@Override
	public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
		log.debug("登录或认证:获取客户端对应的SCOPE");
		String secret = oauthService.getSecretByClientId(clientId);
		if (StringUtils.isEmpty(secret)) {
			log.error(clientId + "客户端不存在");
			throw new UsernameNotFoundException(clientId + "客户端不存在");
		}

		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId(clientId);
		clientDetails.setClientSecret(secret);
		// 接收认证码的url
		clientDetails.setRegisteredRedirectUri( oauthService.getRegisteredRedirectUriByClientId(clientId) );
		clientDetails.setAuthorizedGrantTypes(
				Arrays.asList("authorization_code", "refresh_token", "implicit", "password", "client_credentials"));
		// 客户端的权限
		clientDetails.setScope( oauthService.getScopesByClientId(clientId));
		clientDetails.setAutoApproveScopes(oauthService.getAutoApproveScopesByClientId(clientId));
		clientDetails.setAccessTokenValiditySeconds(oauthService.getAccessTokenValiditySeconds());
		return clientDetails;

	}

}