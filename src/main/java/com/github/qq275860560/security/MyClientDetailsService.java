package com.github.qq275860560.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.stereotype.Service;

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
		return securityService.getClientDetailsByClientId(clientId);
	}

}