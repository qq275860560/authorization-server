package com.github.qq275860560.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Component
@Slf4j
public class MyJwtTokenStore extends JwtTokenStore {	 
	@Autowired
	public   MyJwtTokenStore(MyJwtAccessTokenConverter myJwtAccessTokenConverter) {
		super(myJwtAccessTokenConverter);
	}
}
