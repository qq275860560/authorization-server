package com.github.qq275860560.security;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.qq275860560.service.OauthService;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Component
@Slf4j
public class MyAuthorizationCodeServices implements AuthorizationCodeServices {
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private RsaSigner rsaSigner;
	@Autowired
	private RsaVerifier rsaVerifier;
	@Autowired
	private OauthService oauthService;

	@Override
	public String createAuthorizationCode(OAuth2Authentication authentication) {
		try {

			String subject = objectMapper.writeValueAsString(authentication);

			return JwtHelper.encode(subject, rsaSigner).getEncoded();
		} catch (Exception e) {
			log.error("", e);

		}
		return null;
	}

	@Override
	public OAuth2Authentication consumeAuthorizationCode(String code) throws InvalidGrantException {
		try {
			String subject =  JwtHelper.decodeAndVerify(code, rsaVerifier).getClaims();

			Map<String, Object> subjectMap = objectMapper.readValue(subject, Map.class);

			Map<String, Object> map = (Map<String, Object>) subjectMap.get("oauth2Request");

			OAuth2Request storedRequest = new OAuth2Request((Map<String, String>) map.get("requestParameters"),
					(String) map.get("clientId"), (Collection<? extends GrantedAuthority>) map.get("authorities"),
					(Boolean) map.get("approved"), new HashSet((List) map.get("scope")),
					new HashSet((List) map.get("resourceIds")), (String) map.get("redirectUri"),
					new HashSet((List) map.get("responseTypes")), (Map<String, Serializable>) map.get("extensions"));

			map = (Map<String, Object>) subjectMap.get("userAuthentication");
			Authentication userAuthentication = new UsernamePasswordAuthenticationToken(

					new User((String) ((Map<String, Object>) map.get("principal")).get("username"),
							(String) ((Map<String, Object>) map.get("principal")).get("password"),
							(Boolean) ((Map<String, Object>) map.get("principal")).get("enabled"),
							(Boolean) ((Map<String, Object>) map.get("principal")).get("accountNonExpired"),
							(Boolean) ((Map<String, Object>) map.get("principal")).get("credentialsNonExpired"),
							(Boolean) ((Map<String, Object>) map.get("principal")).get("accountNonLocked"),

							(Collection<? extends GrantedAuthority>)

							((List<Map<String, String>>) ((Map<String, Object>) map.get("principal"))
									.get("authorities")).stream().map(a -> new GrantedAuthority() {

										public String getAuthority() {

											return a.get("authority");
										}
									}).collect(Collectors.toList())

					)

					, map.get("credentials"),
					((List<Map<String, String>>) map.get("authorities")).stream().map(a -> new GrantedAuthority() {

						public String getAuthority() {

							return a.get("authority");
						}
					}).collect(Collectors.toList())

			);

			return new OAuth2Authentication(storedRequest, userAuthentication);

		} catch (Exception e) {
			log.error("", e);
		}
		return null;

	}

}
