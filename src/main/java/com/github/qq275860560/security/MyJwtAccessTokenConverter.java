package com.github.qq275860560.security;

import java.security.KeyPair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;

import com.github.qq275860560.service.SecurityService;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Component
@Slf4j
public class MyJwtAccessTokenConverter extends JwtAccessTokenConverter {
 
	 

	 
	@Autowired
	public   MyJwtAccessTokenConverter(KeyPair keyPair) {
		//this.setSigner(rsaSigner);// 如果只是资源服务器，可以不设置
		//this.setVerifier(rsaVerifier);
		try {
		this.setKeyPair(keyPair);
		}catch (Exception e) {
			log.error("",e);
		}
	}
	

	 
}
