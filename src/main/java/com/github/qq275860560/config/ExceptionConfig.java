package com.github.qq275860560.config;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 */
@Configuration
@Slf4j
public class ExceptionConfig implements WebMvcConfigurer {

	@Override
	public void configureHandlerExceptionResolvers(List<HandlerExceptionResolver> resolvers) {
		resolvers.add(0, (request, response, o, e) -> {
			handleResponse(response, e);
			return null;
		});
	}

	public static void handleResponse(HttpServletResponse response, Exception e) {
		log.error("", e);
		response.setCharacterEncoding("UTF-8");
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		try {
			PrintWriter out = response.getWriter();
			out.println(new ObjectMapper().writeValueAsString(new HashMap<String, Object>() {
				{
					put("code", response.getStatus());
					put("msg", e.getMessage());
					put("data", null);
				}
			}));
			out.flush();
			out.close();
		} catch (Exception ex) {
			log.error("", ex);
		}
	}

}