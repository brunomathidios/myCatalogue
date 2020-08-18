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
	            return "/error/404";
	        }
	        else if(statusCode == HttpStatus.FORBIDDEN.value()) {
	            return "/error/403";
	        }
	        else if(statusCode == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
	            return "/error/500";
	        }
	    }
	    return "/error/500";
	}
	
	@GetMapping("/403")
    public String error403() {
        return "/error/403";
    }
    
    @GetMapping("/404")
    public String error404() {
        return "/error/404";
    }
    
    @GetMapping("/500")
    public String error500() {
        return "/error/500";
    }

}
