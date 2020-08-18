package org.sid.controller;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ErrorsController implements ErrorController {
	
	private static final Logger LOG = LoggerFactory.getLogger(ErrorsController.class);

	@Override
	public String getErrorPath() {
		LOG.error("ENTROU NO METODO ERROR PATH");
		return "/error";
	}
	
	@RequestMapping("/error")
	public String handleError(HttpServletRequest request) {
	    Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
	    String error = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
	    
	    LOG.error(error);
	     
	    if (status != null) {
	        Integer statusCode = Integer.valueOf(status.toString());
	     
	        if(statusCode == HttpStatus.NOT_FOUND.value()) {
	        	LOG.error("ENCONTROU O ERRO 404");
	            return "404";
	        }
	        else if(statusCode == HttpStatus.FORBIDDEN.value()) {
	        	LOG.error("ENCONTROU O ERRO 403");
	            return "403";
	        }
	        else if(statusCode == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
	        	LOG.error("ENCONTROU O ERRO 500");
	            return "500";
	        }
	    }
	    return "500";
	}
	
}
