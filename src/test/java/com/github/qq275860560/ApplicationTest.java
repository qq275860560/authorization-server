package com.github.qq275860560;

import java.util.List;
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

import ch.qos.logback.core.net.LoginAuthenticator;
import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@SuppressWarnings(value= {"serial" ,"rawtypes"})
@Slf4j
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class ApplicationTest {

	@Autowired
	private TestRestTemplate testRestTemplate;


 

	@Test
	public void oauth2_password() {
		// SCOPE为普通客户端登录

		ResponseEntity<Map> response = testRestTemplate.withBasicAuth("client1", "123456").exchange(
				"/oauth/token?grant_type=password&username=username1&password=123456", HttpMethod.GET, null,
				Map.class);
		String access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save错误(没有权限)
		response = testRestTemplate.exchange("/api/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(403, response.getStatusCode().value());

		// SCOPE为管理员客户端登录
		response = testRestTemplate.withBasicAuth("admin", "123456").exchange(
				"/oauth/token?grant_type=password&username=username1&password=123456", HttpMethod.GET, null,
				Map.class);
		access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save正常
		response = testRestTemplate.exchange("/api/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

	}

	@Test
	public void oauth2_client_credentials() {

		// SCOPE为普通客户端登录

		ResponseEntity<Map> response = testRestTemplate.withBasicAuth("client1", "123456")
				.exchange("/oauth/token?grant_type=client_credentials", HttpMethod.GET, null, Map.class);
		String access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save错误(没有权限)
		response = testRestTemplate.exchange("/api/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(403, response.getStatusCode().value());

		// SCOPE为管理员客户端登录
		response = testRestTemplate.withBasicAuth("admin", "123456")
				.exchange("/oauth/token?grant_type=client_credentials", HttpMethod.GET, null, Map.class);
		access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save正常
		response = testRestTemplate.exchange("/api/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

	}

	@Test
	public void oauth2_authorization_code() {
		// SCOPE为普通客户端登录
		ResponseEntity<Map> response = testRestTemplate.exchange("/login?username=username1&password=123456",
				HttpMethod.POST, null, Map.class);
		List<String> session =   response.getHeaders().get("Set-Cookie");

		response = testRestTemplate.exchange("/oauth/authorize?client_id=client1&response_type=code", HttpMethod.GET,
				new HttpEntity<>(new HttpHeaders() {
					{
						put("Cookie", session);
						 
					}
				}), Map.class);
		String location = response.getHeaders().getLocation().getRawQuery();
		String code = location.split("=")[1];

		response = testRestTemplate.exchange(
				"/oauth/token?grant_type=authorization_code&client_id=client1&client_secret=123456&scope=USER&code="
						+ code,
				HttpMethod.GET, null, Map.class);
		String access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save错误(没有权限)
		response = testRestTemplate.exchange("/api/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(403, response.getStatusCode().value());

		// SCOPE为管理员客户端登录
		 response = testRestTemplate.exchange("/login?username=username1&password=123456",
				HttpMethod.POST, null, Map.class);
		List<String> session2 =   response.getHeaders().get("Set-Cookie");
		

		response = testRestTemplate.exchange("/oauth/authorize?client_id=admin&response_type=code", HttpMethod.GET,
				new HttpEntity<>(new HttpHeaders() {
					{
						put("Cookie", session2);
					}
				}), Map.class);
		location = response.getHeaders().getLocation().getRawQuery();
		code = location.split("=")[1];

		response = testRestTemplate.exchange(
				"/oauth/token?grant_type=authorization_code&client_id=admin&client_secret=123456&scope=ADMIN&code="
						+ code,
				HttpMethod.GET, null, Map.class);
		access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save正常
		response = testRestTemplate.exchange("/api/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

	}

	@Test
	public void oauth2_refresh_token() {
	 
		// SCOPE为普通客户端登录
				ResponseEntity<Map> response = testRestTemplate.exchange("/login?username=username1&password=123456",
						HttpMethod.POST, null, Map.class);
				List<String> session =   response.getHeaders().get("Set-Cookie");

				response = testRestTemplate.exchange("/oauth/authorize?client_id=client1&response_type=code", HttpMethod.GET,
						new HttpEntity<>(new HttpHeaders() {
							{
								put("Cookie", session);
								 
							}
						}), Map.class);
				String location = response.getHeaders().getLocation().getRawQuery();
				String code = location.split("=")[1];

	 

		response = testRestTemplate.exchange(
				"/oauth/token?grant_type=authorization_code&client_id=client1&client_secret=123456&scope=USER&code="
						+ code,
				HttpMethod.GET, null, Map.class);
		String refresh_token = (String) response.getBody().get("refresh_token");
		log.info("" + refresh_token);
		Assert.assertTrue(refresh_token.length() > 0);

		response = testRestTemplate
				.exchange("/oauth/token?grant_type=refresh_token&client_id=client1&client_secret=123456&refresh_token="
						+ refresh_token, HttpMethod.GET, null, Map.class);
		String access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save错误(没有权限)
		response = testRestTemplate.exchange("/api/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(403, response.getStatusCode().value());

		// SCOPE为管理员客户端登录
		 response = testRestTemplate.exchange("/login?username=username1&password=123456",
					HttpMethod.POST, null, Map.class);
			List<String> session2 =   response.getHeaders().get("Set-Cookie");
			

			response = testRestTemplate.exchange("/oauth/authorize?client_id=admin&response_type=code", HttpMethod.GET,
					new HttpEntity<>(new HttpHeaders() {
						{
							put("Cookie", session2);
						}
					}), Map.class);
			location = response.getHeaders().getLocation().getRawQuery();
			code = location.split("=")[1];
			
	
		response = testRestTemplate.exchange(
				"/oauth/token?grant_type=authorization_code&client_id=admin&client_secret=123456&scope=ADMIN&code="
						+ code,
				HttpMethod.GET, null, Map.class);
		refresh_token = (String) response.getBody().get("refresh_token");
		log.info("" + refresh_token);
		Assert.assertTrue(refresh_token.length() > 0);

		response = testRestTemplate
				.exchange("/oauth/token?grant_type=refresh_token&client_id=admin&client_secret=123456&refresh_token="
						+ refresh_token, HttpMethod.GET, null, Map.class);
		access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 错误(没有认证)
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient", HttpMethod.GET, null, Map.class);
		Assert.assertEquals(401, response.getStatusCode().value());

		// get正常
		response = testRestTemplate.exchange("/api/github/qq275860560/client/getClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

		// save正常
		response = testRestTemplate.exchange("/api/github/qq275860560/client/saveClient?access_token=" + access_token, HttpMethod.GET, null,
				Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals(200, response.getBody().get("code"));

	}

	@Test
	public void oauth2_check_token() {

		// SCOPE为普通客户端登录

		ResponseEntity<Map> response = testRestTemplate.withBasicAuth("client1", "123456")
				.exchange("/oauth/token?grant_type=client_credentials", HttpMethod.GET, null, Map.class);
		String access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 校验正常
		response = testRestTemplate.withBasicAuth("client1", "123456")
				.exchange("/oauth/check_token?token=" + access_token, HttpMethod.GET, null, Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals("client1", response.getBody().get("client_id"));

		// SCOPE为管理员客户端登录
		response = testRestTemplate.withBasicAuth("admin", "123456")
				.exchange("/oauth/token?grant_type=client_credentials", HttpMethod.GET, null, Map.class);
		access_token = (String) response.getBody().get("access_token");
		log.info("" + access_token);
		Assert.assertTrue(access_token.length() > 0);

		// 校验正常
		response = testRestTemplate.withBasicAuth("admin", "123456").exchange("/oauth/check_token?token=" + access_token,
				HttpMethod.GET, null, Map.class);
		Assert.assertEquals(200, response.getStatusCode().value());
		Assert.assertEquals("admin", response.getBody().get("client_id"));

	}
	
	
	
	@Test
	public void oauth2_token_key() {

		// SCOPE为普通客户端登录

		ResponseEntity<Map> response = testRestTemplate.withBasicAuth("client1", "123456")
				.exchange("/oauth/token_key", HttpMethod.GET, null, Map.class);
		String public_key = (String) response.getBody().get("value");
		log.info("" + public_key);
		Assert.assertTrue(public_key.length() > 0);

		 
	}
}

/**

//传统

session=`curl  -i -X POST 'http://localhost:8080/login?username=username1&password=123456'    | grep Set-Cookie | awk -F " " '{print $2}'`
echo 当前session为$session
curl -i -X POST "http://localhost:8080/api/github/qq275860560/user/pageUser?pageNum=1&pageSize=10" -H "Cookie:$session" 

session=`curl  -i -X POST 'http://localhost:8080/login?username=admin&password=123456'    | grep Set-Cookie | awk -F " " '{print $2}'`
echo 当前session为$session
curl -i -X GET "http://localhost:8080/api/github/qq275860560/user/saveUser?username=username2" -H "Cookie:$session" 

//oauth2客户端模式
token=`curl -i -X POST "http://client1:123456@localhost:8080/oauth/token?grant_type=client_credentials"  | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X POST "http://localhost:8080/api/github/qq275860560/client/getClient?access_token=$token"



//oauth2密码模式
token=`curl -i -X POST "http://client1:123456@localhost:8080/oauth/token?grant_type=password&username=username1&password=123456"  | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X POST "http://localhost:8080/api/github/qq275860560/client/getClient?access_token=$token"

token=`curl -i -X POST "http://client1:123456@localhost:8080/oauth/token?grant_type=password&username=username1&password=123456"  | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X POST "http://localhost:8080/api/github/qq275860560/client/pageClient?access_token=$token"

//oauth2认证码模式   
session=`curl  -i -X POST 'http://localhost:8080/login?username=username1&password=123456'    | grep Set-Cookie | awk -F " " '{print $2}'`
echo 当前session为$session 
code=`curl -i -X GET "http://localhost:8080/oauth/authorize?client_id=client1&response_type=code"   -H "Cookie:$session"   | grep Location | cut -d'=' -f2` 
echo 当前认证码为$code
token=`curl -i -X POST "http://localhost:8080/oauth/token?grant_type=authorization_code&client_id=client1&client_secret=123456&scope=USER&code=$code"  | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X POST "http://localhost:8080/api/github/qq275860560/client/getClient?access_token=$token"


//oauth2刷新token
session=`curl  -i -X POST 'http://localhost:8080/login?username=username1&password=123456'    | grep Set-Cookie | awk -F " " '{print $2}'`
echo 当前session为$session
code=`curl -i -X GET "http://localhost:8080/oauth/authorize?client_id=client1&response_type=code"   -H "Cookie:$session"   | grep Location | cut -d'=' -f2` 
echo 当前认证码为$code
refresh_token=`curl -i -X POST "http://localhost:8080/oauth/token?grant_type=authorization_code&client_id=client1&client_secret=123456&scope=USER&code=$code"  | grep refresh_token | awk -F "\"" '{print $12}'`
echo 当前refresh_token为$refresh_token
token=`curl -i -X POST "http://localhost:8080/oauth/token?grant_type=refresh_token&client_id=client1&client_secret=123456&refresh_token=${refresh_token}"  | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X POST "http://localhost:8080/api/github/qq275860560/client/getClient?access_token=$token"                    

//oauth2校验token
token=`curl -i -X POST "http://client1:123456@localhost:8080/oauth/token?grant_type=client_credentials"  | grep access_token | awk -F "\"" '{print $4}'`
echo 当前token为$token
curl -i -X POST  "http://client1:123456@localhost:8080/oauth/check_token?token=$token"                   
            
 */