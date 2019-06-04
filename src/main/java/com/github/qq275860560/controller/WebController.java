package com.github.qq275860560.controller;

import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import lombok.extern.slf4j.Slf4j;

@Controller
@Slf4j
public class WebController {

	@RequestMapping(value = "/helloworld")
	public void hellworld(HttpServletResponse response) throws Exception{
		 response.getWriter().write("hello world");		
	}

	 
}
