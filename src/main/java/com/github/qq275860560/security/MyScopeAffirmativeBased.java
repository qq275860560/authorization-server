package com.github.qq275860560.security;

import java.util.Arrays;

import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.oauth2.provider.vote.ScopeVoter;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * @author jiangyuanlin@163.com
 *  
 */

@Component
@Slf4j
public class MyScopeAffirmativeBased extends AffirmativeBased {
	 public MyScopeAffirmativeBased() {		  
			super(Arrays.asList(new WebExpressionVoter(),
					new ScopeVoter(),
					new AuthenticatedVoter()));
	 }
}