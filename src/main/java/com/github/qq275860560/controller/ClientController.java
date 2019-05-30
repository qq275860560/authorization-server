package com.github.qq275860560.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class ClientController {

	@RequestMapping(value = "/oauth2/github/qq275860560/client/getClient")
	public Map<String, Object> getClient() {
		OAuth2Authentication oAuth2Authentication =  (OAuth2Authentication)SecurityContextHolder.getContext().getAuthentication();
		String username= oAuth2Authentication.getUserAuthentication()==null?null:oAuth2Authentication.getUserAuthentication().getName();
		String clientId=oAuth2Authentication.getOAuth2Request().getClientId(); 
		log.info("资源用户名称=" + username+",客户端id="+clientId);
		return new HashMap<String, Object>() {
			{
				put("code", HttpStatus.OK.value());
				put("msg", "获取成功");
				put("data", null);
			}
		};
	}

	@RequestMapping("/oauth2/github/qq275860560/client/saveClient")
	public Map<String, Object> saveClient() {
		OAuth2Authentication oAuth2Authentication =  (OAuth2Authentication)SecurityContextHolder.getContext().getAuthentication();
		String username= oAuth2Authentication.getUserAuthentication()==null?null:oAuth2Authentication.getUserAuthentication().getName();
		String clientId=oAuth2Authentication.getOAuth2Request().getClientId(); 
		log.info("资源用户名称=" + username+",客户端id="+clientId);
		return new HashMap<String, Object>() {
			{
				put("code", HttpStatus.OK.value());
				put("msg", "保存成功");
				put("data", null);
			}
		};
	}

}
