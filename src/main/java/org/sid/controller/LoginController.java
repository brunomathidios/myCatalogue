package org.sid.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

	@GetMapping("/")
    public String root() {
        return "/home";
    }
	
	@GetMapping("/home")
    public String home() {
        return "/home";
    }

    @GetMapping("/login")
    public String login() {
        return "/login";
    }
    
    @GetMapping("/403")
    public String error403() {
        return "/error/403";
    }
    
}
