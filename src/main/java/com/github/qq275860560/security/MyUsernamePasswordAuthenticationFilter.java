package com.github.qq275860560.security;

import java.io.IOException;
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
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Base64Utils;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.qq275860560.service.SecurityService;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */
@Slf4j
public class MyUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private ObjectMapper objectMapper;
	private RestTemplate  restTemplate;
	private SecurityService  securityService;
//	private MyUserDetailsService myUserDetailsService;
//	private MyPasswordEncoder myPasswordEncoder;
	// curl -i -X GET "http://localhost:8080/login?username=username1&password=123456"

	public MyUsernamePasswordAuthenticationFilter(ObjectMapper objectMapper, RestTemplate restTemplate,
			SecurityService gatewayService) {
		super.setPostOnly(false);
		super.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login"));
		this.objectMapper = objectMapper;
		this.restTemplate = restTemplate;
		this.securityService = gatewayService;
//		this.myUserDetailsService = myUserDetailsService;
//		this.myPasswordEncoder = myPasswordEncoder;
	
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

			// 如果网关和认证中心在不同tomcat,向认证服务器发起请求，
			ResponseEntity<Map> result = restTemplate
					.exchange(
							securityService.getAuthorizationServerUrl() + "/oauth/token?grant_type=password&username="
									+ username + "&password=" + password,
							HttpMethod.POST, new HttpEntity<>(new HttpHeaders() {
								{
									setBasicAuth(securityService.getClientDetails().getClientId(), securityService.getClientDetails().getClientSecret());
								}
							}), Map.class);
			HttpHeaders entityHeaders = result.getHeaders();
			entityHeaders.forEach((key, value) -> {
				value.forEach((headerValue) -> {
					response.addHeader(key, headerValue);
				});
			});
			response.getWriter().write(objectMapper.writeValueAsString(result.getBody()));
			response.getWriter().flush();
			 
			/*String encoding =    Base64Utils.encodeToString((securityService.getClientDetails().getClientId()+":"+securityService.getClientDetails().getClientSecret()).getBytes());
			response.setHeader("Authorization", "Basic " + encoding);
			request.getRequestDispatcher("/oauth/token").forward(request, response);
			*/
			//如果网关和认证中心在同一tomcat，则仿照/oauth/token直接认证，减少http请求
			/*ClientDetails clientDetails = securityService.getClientDetails();
			Set<String> scope = securityService.getClientDetailsByClientId(clientDetails.getClientId()).getScope();
			Collection<GrantedAuthority>  authorities = securityService.getClientDetailsByClientId(clientDetails.getClientId()).getAuthorities();
			Set<String>  authorizedGrantTypes = securityService.getClientDetailsByClientId(clientDetails.getClientId()).getAuthorizedGrantTypes();

			OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(new OAuth2Request( 
					 null, clientDetails.getClientId(), authorities,true,  
							scope, null, null, authorizedGrantTypes , null)
					
					,null);
			 tokenEndpoint.postAccessToken(oAuth2Authentication, new HashMap<String, String>(){{
				 put("grant_type","password");put("username",username);put("password",password);
				 
			 }});*/
			
			/*UserDetails userDetails = myUserDetailsService.loadUserByUsername(username);
			if (userDetails == null) {
				throw new Exception("用户不存在");
			} else if (!myPasswordEncoder.matches(password, userDetails.getPassword())) {
				throw new Exception("密码错误");
			}

			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails,
					userDetails.getPassword(), userDetails.getAuthorities());
			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails((HttpServletRequest) request));

			ClientDetails clientDetails = securityService.getClientDetails();
			Set<String> scope = securityService.getClientDetailsByClientId(clientDetails.getClientId()).getScope();

			TokenRequest tokenRequest = new TokenRequest(new HashMap<>(), clientDetails.getClientId(), scope,
					"password");

			OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);

			OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, authentication);

			OAuth2AccessToken token = myDefaultTokenServices.createAccessToken(oAuth2Authentication);
			response.setContentType("application/json;charset=UTF-8");
			response.getWriter().write(objectMapper.writeValueAsString(token));
			response.getWriter().flush();
*/
		} catch (Exception e) {
			unsuccessfulAuthentication((HttpServletRequest) req, (HttpServletResponse) res,
					new AuthenticationServiceException(e.getMessage(), e));
		}

	}
}