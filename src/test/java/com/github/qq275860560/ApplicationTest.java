package com.github.qq275860560;

import java.util.Map;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@SuppressWarnings(value= {"serial" ,"rawtypes"})
@Slf4j
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ApplicationTest {

	@Autowired
	private TestRestTemplate testRestTemplate;

	@Test
	public void login() throws Exception {

		// ROLE为普通客户端登录

		ResponseEntity<Map> response = testRestTemplate.exchange("/login?username=username1&password=password1",
				HttpMethod.GET, null, Map.class);
		String access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/api/github/qq275860560/user/pageUser?pageNum=1&pageSize=10",
				HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/api/github/qq275860560/user/pageUser?pageNum=1&pageSize=10",
				HttpMethod.GET, new HttpEntity<>(new HttpHeaders() {
					{
						setBearerAuth(access_token);
					}
				}), Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save错误(没有权限)
		response = testRestTemplate.exchange("/api/github/qq275860560/user/saveUser?username=username2", HttpMethod.GET,
				new HttpEntity<>(new HttpHeaders() {
					{
						setBearerAuth(access_token);
					}
				}), Map.class);
		Assert.assertEquals(403, response.getStatusCode().value());

		// ROLE为管理员客户端登录
		response = testRestTemplate.exchange("/login?username=admin&password=admin", HttpMethod.GET, null, Map.class);
		String access_token2 = (String) response.getBody().get("access_token");
		log.info("" + access_token2);
		Assert.assertTrue(access_token2.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/api/github/qq275860560/user/pageUser?pageNum=1&pageSize=10",
				HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/api/github/qq275860560/user/pageUser?pageNum=1&pageSize=10",
				HttpMethod.GET, new HttpEntity<>(new HttpHeaders() {
					{
						setBearerAuth(access_token2);
					}
				}), Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save正常
		response = testRestTemplate.exchange("/api/github/qq275860560/user/saveUser?username=username2", HttpMethod.GET,
				new HttpEntity<>(new HttpHeaders() {
					{
						setBearerAuth(access_token2);
					}
				}), Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

	}

	@Test
	public void oauth2_password() {
		// SCOPE为普通客户端登录

		ResponseEntity<Map> response = testRestTemplate.withBasicAuth("client1", "secret1").exchange(
				"/oauth/token?grant_type=password&username=username1&password=password1", HttpMethod.GET, null,
				Map.class);
		String access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save错误(没有权限)
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(403, response.getStatusCode().value());

		// SCOPE为管理员客户端登录
		response = testRestTemplate.withBasicAuth("admin", "admin").exchange(
				"/oauth/token?grant_type=password&username=username1&password=password1", HttpMethod.GET, null,
				Map.class);
		access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save正常
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

	}

	@Test
	public void oauth2_client_credentials() {

		// SCOPE为普通客户端登录

		ResponseEntity<Map> response = testRestTemplate.withBasicAuth("client1", "secret1")
				.exchange("/oauth/token?grant_type=client_credentials", HttpMethod.GET, null, Map.class);
		String access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save错误(没有权限)
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(403, response.getStatusCode().value());

		// SCOPE为管理员客户端登录
		response = testRestTemplate.withBasicAuth("admin", "admin")
				.exchange("/oauth/token?grant_type=client_credentials", HttpMethod.GET, null, Map.class);
		access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save正常
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

	}

	@Test
	public void oauth2_authorization_code() {
		// SCOPE为普通客户端登录
		ResponseEntity<Map> response = testRestTemplate.exchange("/login?username=username1&password=password1",
				HttpMethod.GET, null, Map.class);
		String tmp_access_token = (String) response.getBody().get("access_token");

		response = testRestTemplate.exchange("/oauth/authorize?client_id=client1&response_type=code", HttpMethod.GET,
				new HttpEntity<>(new HttpHeaders() {
					{
						setBearerAuth(tmp_access_token);
					}
				}), Map.class);
		String location = response.getHeaders().getLocation().getRawQuery();
		String code = location.split("=")[1];

		response = testRestTemplate.exchange(
				"/oauth/token?grant_type=authorization_code&client_id=client1&client_secret=secret1&scope=USER&code="
						+ code,
				HttpMethod.GET, null, Map.class);
		String access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save错误(没有权限)
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(403, response.getStatusCode().value());

		// SCOPE为管理员客户端登录
		response = testRestTemplate.exchange("/login?username=username1&password=password1", HttpMethod.GET, null,
				Map.class);
		String tmp_access_token2 = (String) response.getBody().get("access_token");

		response = testRestTemplate.exchange("/oauth/authorize?client_id=admin&response_type=code", HttpMethod.GET,
				new HttpEntity<>(new HttpHeaders() {
					{
						setBearerAuth(tmp_access_token2);
					}
				}), Map.class);
		location = response.getHeaders().getLocation().getRawQuery();
		code = location.split("=")[1];

		response = testRestTemplate.exchange(
				"/oauth/token?grant_type=authorization_code&client_id=admin&client_secret=admin&scope=ADMIN&code="
						+ code,
				HttpMethod.GET, null, Map.class);
		access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save正常
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

	}

	@Test
	public void oauth2_refresh_token() {
		// SCOPE为普通客户端登录
		ResponseEntity<Map> response = testRestTemplate.exchange("/login?username=username1&password=password1",
				HttpMethod.GET, null, Map.class);
		String tmp_access_token = (String) response.getBody().get("access_token");

		response = testRestTemplate.exchange("/oauth/authorize?client_id=client1&response_type=code", HttpMethod.GET,
				new HttpEntity<>(new HttpHeaders() {
					{
						setBearerAuth(tmp_access_token);
					}
				}), Map.class);
		String location = response.getHeaders().getLocation().getRawQuery();
		String code = location.split("=")[1];

		response = testRestTemplate.exchange(
				"/oauth/token?grant_type=authorization_code&client_id=client1&client_secret=secret1&scope=USER&code="
						+ code,
				HttpMethod.GET, null, Map.class);
		String refresh_token = (String) response.getBody().get("refresh_token");
		log.info("" + refresh_token);
		Assert.assertTrue(refresh_token.length() > 0);

		response = testRestTemplate
				.exchange("/oauth/token?grant_type=refresh_token&client_id=client1&client_secret=secret1&refresh_token="
						+ refresh_token, HttpMethod.GET, null, Map.class);
		String access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save错误(没有权限)
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(403, response.getStatusCode().value());

		// SCOPE为管理员客户端登录
		response = testRestTemplate.exchange("/login?username=username1&password=password1", HttpMethod.GET, null,
				Map.class);
		String tmp_access_token2 = (String) response.getBody().get("access_token");

		response = testRestTemplate.exchange("/oauth/authorize?client_id=admin&response_type=code", HttpMethod.GET,
				new HttpEntity<>(new HttpHeaders() {
					{
						setBearerAuth(tmp_access_token2);
					}
				}), Map.class);
		location = response.getHeaders().getLocation().getRawQuery();
		code = location.split("=")[1];

		response = testRestTemplate.exchange(
				"/oauth/token?grant_type=authorization_code&client_id=admin&client_secret=admin&scope=ADMIN&code="
						+ code,
				HttpMethod.GET, null, Map.class);
		refresh_token = (String) response.getBody().get("refresh_token");
		log.info("" + refresh_token);
		Assert.assertTrue(refresh_token.length() > 0);

		response = testRestTemplate
				.exchange("/oauth/token?grant_type=refresh_token&client_id=admin&client_secret=admin&refresh_token="
						+ refresh_token, HttpMethod.GET, null, Map.class);
		access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save正常
		response = testRestTemplate.exchange("/oauth2/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

	}

	@Test
	public void oauth2_check_token() {

		// SCOPE为普通客户端登录

		ResponseEntity<Map> response = testRestTemplate.withBasicAuth("client1", "secret1")
				.exchange("/oauth/token?grant_type=client_credentials", HttpMethod.GET, null, Map.class);
		String access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 校验正常
		response = testRestTemplate.withBasicAuth("client1", "secret1")
				.exchange("/oauth/check_token?token=" + access_token, HttpMethod.GET, null, Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals("client1", response.getBody().get("client_id"));

		// SCOPE为管理员客户端登录
		response = testRestTemplate.withBasicAuth("admin", "admin")
				.exchange("/oauth/token?grant_type=client_credentials", HttpMethod.GET, null, Map.class);
		access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 校验正常
		response = testRestTemplate.withBasicAuth("admin", "admin").exchange("/oauth/check_token?token=" + access_token,
				HttpMethod.GET, null, Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals("admin", response.getBody().get("client_id"));

	}
	
	
	
	@Test
	public void oauth2_token_key() {

		// SCOPE为普通客户端登录

		ResponseEntity<Map> response = testRestTemplate.withBasicAuth("client1", "secret1")
				.exchange("/oauth/token_key", HttpMethod.GET, null, Map.class);
		String public_key = (String) response.getBody().get("value");
		log.info("" + public_key);
		Assert.assertTrue(public_key.length() > 0);

		 
	}
}