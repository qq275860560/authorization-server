package com.github.qq275860560.security;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.qq275860560.service.ClientService;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Slf4j
public class MyUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private ObjectMapper objectMapper;
	private RestTemplate  restTemplate;
	private ClientService  clientService;
	// curl -i -X GET "http://localhost:8080/login?username=username1&password=123456"

	public MyUsernamePasswordAuthenticationFilter(ObjectMapper objectMapper, RestTemplate restTemplate,
			ClientService clientService) {
		super.setPostOnly(false);
		super.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login"));
		this.objectMapper = objectMapper;
		this.restTemplate = restTemplate;
		this.clientService = clientService;
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		try {
			/*****拷贝自AbstractAuthenticationProcessingFilter.doFilter*****/
			HttpServletRequest request = (HttpServletRequest) req;
			HttpServletResponse response = (HttpServletResponse) res;

			if (!requiresAuthentication(request, response)) {
				chain.doFilter(request, response);

				return;
			}

			if (logger.isDebugEnabled()) {
				logger.debug("Request is to process authentication");
			}
			/*****拷贝自AbstractAuthenticationProcessingFilter.doFilter*****/

			/*****拷贝自UsernamePasswordAuthenticationFilter.attemptAuthentication*****/
			String username = obtainUsername(request);
			String password = obtainPassword(request);

			if (username == null) {
				username = "";
			}

			if (password == null) {
				password = "";
			}

			username = username.trim();
			/*****拷贝自UsernamePasswordAuthenticationFilter.attemptAuthentication*****/

			// 向认证服务器发起请求

			ResponseEntity<Map> result = restTemplate
					.exchange(
							clientService.getAuthorizationServerUrl() + "/oauth/token?grant_type=password&username="
									+ username + "&password=" + password,
							HttpMethod.POST, new HttpEntity<>(new HttpHeaders() {
								{
									setBasicAuth(clientService.getClient().get("client_id"), clientService.getClient().get("client_secret"));
								}
							}), Map.class);
			String access_token = (String) result.getBody().get("access_token");

			HttpHeaders entityHeaders = result.getHeaders();
			entityHeaders.forEach((key, value) -> {
				value.forEach((headerValue) -> {
					response.addHeader(key, headerValue);
				});
			});
			response.getWriter().write(objectMapper.writeValueAsString(result.getBody()));
			response.getWriter().flush();

			//
		} catch (Exception e) {
			unsuccessfulAuthentication((HttpServletRequest) req, (HttpServletResponse) res,
					new AuthenticationServiceException(e.getMessage(), e));
		}

	}
}