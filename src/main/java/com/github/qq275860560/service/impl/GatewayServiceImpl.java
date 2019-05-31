package com.github.qq275860560.service.impl;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.web.client.RestTemplate;

import com.github.qq275860560.service.GatewayService;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Component
@Slf4j
public class GatewayServiceImpl extends GatewayService {

	public Map<String, String> getClient() {
		return new HashMap<String, String>() {
			{
				put("client_id", "gateway");
				put("client_secret", "123456");
			}
		};
	}

	public String getAuthorizationServerUrl() {
		return "http://localhost:8080";
	}

	@Autowired
	private RestTemplate restTemplate;

	private RsaVerifier rsaVerifier;

	/**
	 * 获取认证授权服务器的公钥
	 * 默认第一次访问的时候，加载认证授权服务器的公钥,
	 * 如果应用本身也是认证服务器读取配置文件
	 * 如果认证授权逻辑不再该应用中，通过默认的/oauth/token_key加载公钥
	 * @return 公钥
	 */
	@Override
	public RsaVerifier getRsaVerifier() {

		if (rsaVerifier == null) {
			try {
				ResponseEntity<Map> result = restTemplate.exchange(getAuthorizationServerUrl() + "/oauth/token_key",

						HttpMethod.GET, new HttpEntity<>(new HttpHeaders() {
							{
								setBasicAuth(getClient().get("client_id"), getClient().get("client_secret"));
							}
						}), Map.class);
				String public_key = (String) result.getBody().get("value");
				public_key=public_key.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("\n-----END PUBLIC KEY-----", "");
				byte[] keyBytes = Base64Utils.decode(public_key.getBytes());
				X509EncodedKeySpec keySpec_publicKey = new X509EncodedKeySpec(keyBytes);
				KeyFactory keyFactory_publicKey = KeyFactory.getInstance("RSA");
				PublicKey publicKey = keyFactory_publicKey.generatePublic(keySpec_publicKey);

				rsaVerifier = new RsaVerifier((RSAPublicKey) publicKey);

			} catch (Exception e) {
				log.error("", e);
			}

		}

		return rsaVerifier;

	}
}
