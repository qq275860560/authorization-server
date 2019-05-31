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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.qq275860560.service.ClientService;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *
 */

@Slf4j
public class MyRequestHeaderAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	private RestTemplate  restTemplate;
	private ClientService  clientService;

	private MyUserDetailsService myUserDetailsService;

	private MyAuthenticationEntryPoint myAuthenticationEntryPoint;

	private ObjectMapper objectMapper = new ObjectMapper();

	public MyRequestHeaderAuthenticationFilter(AuthenticationManager authenticationManager,
			MyUserDetailsService myUserDetailsService, MyAuthenticationEntryPoint myAuthenticationEntryPoint,RestTemplate restTemplate, ClientService  clientService

	) {

		super.setAuthenticationManager(authenticationManager);
		this.restTemplate=restTemplate;
		this.clientService = clientService;
	
		this.myUserDetailsService = myUserDetailsService;
		this.myAuthenticationEntryPoint = myAuthenticationEntryPoint;

	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		log.debug("认证");
		String header = ((HttpServletRequest) request).getHeader("Authorization");

		if (header == null || !header.startsWith("Bearer ")) {
			chain.doFilter(request, response);
			return;
		}

		try {
			String token = header.replaceAll("Bearer\\s+", "");				
			String payload = JwtHelper.decodeAndVerify(token, clientService.getRsaVerifier()).getClaims();
			String username = (String) objectMapper.readValue(payload, Map.class).get("user_name");
			if (System.currentTimeMillis() / 1000 > (Integer) objectMapper.readValue(payload, Map.class).get("exp")) {
				throw new Exception("token已过期");
			}

			UserDetails userDetails = myUserDetailsService.loadUserByUsername(username);

			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails,
					userDetails.getPassword(), userDetails.getAuthorities());
			// 初始化UserDetail
			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails((HttpServletRequest) request));

			SecurityContextHolder.getContext().setAuthentication(authentication);
		} catch (Exception e) {
			myAuthenticationEntryPoint.commence((HttpServletRequest) request, (HttpServletResponse) response,
					new BadCredentialsException(e.getMessage(), e));
			return;
		}

		chain.doFilter(request, response);
	}

}