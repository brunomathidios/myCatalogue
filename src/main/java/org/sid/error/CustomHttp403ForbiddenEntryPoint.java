package org.sid.error;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

public class CustomHttp403ForbiddenEntryPoint implements AuthenticationEntryPoint {
	
	private static final Logger LOG = LoggerFactory.getLogger(CustomHttp403ForbiddenEntryPoint.class);

	@Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {
		LOG.error("ENTROU NO CUSTOM HTTP 403");
        response.sendRedirect(request.getContextPath() + "403");
    }
}
