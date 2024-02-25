package com.learn.oauth;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpringSecurityResource {

    @GetMapping("/")
    public String information(Authentication authentication) {
        System.out.println(authentication);
        return "Spring Security is a powerful and customizable authentication and access control framework for Java applications. It provides comprehensive security services for Java EE-based enterprise software applications. Spring Security is a part of the larger Spring Framework and is used to secure applications at various levels, including HTTP, method, and domain object security.";
    }
}
