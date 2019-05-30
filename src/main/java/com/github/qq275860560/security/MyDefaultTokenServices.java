package com.github.qq275860560.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Component
@Slf4j
public class MyDefaultTokenServices extends DefaultTokenServices {
	@Autowired
	public MyDefaultTokenServices(MyJwtTokenStore myJwtTokenStore) {
		super.setTokenStore(myJwtTokenStore);
		super.setSupportRefreshToken(true);// 如果只是资源服务器，可以不设置

	}
}
