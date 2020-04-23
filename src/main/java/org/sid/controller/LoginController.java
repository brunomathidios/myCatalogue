package org.sid.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

	@GetMapping("/")
    public String root() {
        return "/login";
    }
	
	@GetMapping("/home")
    public String home() {
        return "/home";
    }

    @GetMapping("/login")
    public String login() {
        return "/login";
    }
    
}
