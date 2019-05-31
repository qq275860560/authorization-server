package com.github.qq275860560.security;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.github.qq275860560.service.SecurityService;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Service
@Slf4j
public class MyClientDetailsService implements ClientDetailsService {

	@Autowired
	private SecurityService securityService;

	@Override
	public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
		log.debug("登录或认证:获取客户端对应的SCOPE");
		String secret = (String)securityService.getClientByClientId(clientId).get("secret");
		if (StringUtils.isEmpty(secret)) {
			log.error(clientId + "客户端不存在");
			throw new UsernameNotFoundException(clientId + "客户端不存在");
		}

		BaseClientDetails clientDetails = new BaseClientDetails();
		clientDetails.setClientId(clientId);
		clientDetails.setClientSecret(secret);
		// 接收认证码的url
		Set<String> registeredRedirectUris = new HashSet<String>(Arrays.asList( ((String)securityService.getClientByClientId(clientId).get("registeredRedirectUris")).split(",")));
	 
			clientDetails.setRegisteredRedirectUri(registeredRedirectUris  );
		 
		Set<String>  authorizedGrantTypes = new HashSet<String>(Arrays.asList( ((String)securityService.getClientByClientId(clientId).get("authorizedGrantTypes")).split(",")));
	 
		clientDetails.setAuthorizedGrantTypes(
				authorizedGrantTypes);
		 
		// 客户端的权限
		Set<String> scopes= new HashSet<String>(Arrays.asList( ((String)securityService.getClientByClientId(clientId).get("scopes")).split(",")));
	 
			clientDetails.setScope(scopes);		
	 
		Set<String> autoApproveScopes=new HashSet<String>(Arrays.asList( ((String)securityService.getClientByClientId(clientId).get("autoApproveScopes")).split(",")));
	 
			clientDetails.setAutoApproveScopes(autoApproveScopes);
	 
		clientDetails.setAccessTokenValiditySeconds((Integer)securityService.getClientByClientId(clientId).get("accessTokenValiditySeconds")   );
		return clientDetails;

	}

}