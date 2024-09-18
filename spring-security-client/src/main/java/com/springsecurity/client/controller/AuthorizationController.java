package com.springsecurity.client.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;

public class AuthorizationController {


    /// Check authentication and AUthorzation of User

    @GetMapping("/api/hello")
    public String sayHello(HttpServletRequest request){
        return "Hello";
    }
}
