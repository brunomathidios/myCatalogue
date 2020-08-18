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
		LOG.error("ENCONTROU NO METODO ERROR PATH");
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
	
	@GetMapping("/403")
    public String error403() {
		LOG.error("VAI RETORNAR PAGINA DE ERRO 403");
        return "/error/403";
    }
    
    @GetMapping("/404")
    public String error404() {
    	LOG.error("VAI RETORNAR PAGINA DE ERRO 404");
        return "/error/404";
    }
    
    @GetMapping("/500")
    public String error500() {
    	LOG.error("VAI RETORNAR PAGINA DE ERRO 500");
        return "/error/500";
    }

}
