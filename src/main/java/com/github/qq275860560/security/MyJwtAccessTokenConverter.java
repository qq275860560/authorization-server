package com.github.qq275860560.security;

import java.security.KeyPair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Component
@Slf4j
public class MyJwtAccessTokenConverter extends JwtAccessTokenConverter {

	@Autowired
	public MyJwtAccessTokenConverter(KeyPair keyPair) {
		try {
			this.setKeyPair(keyPair);
		} catch (Exception e) {
			log.error("", e);
		}
	}

}
