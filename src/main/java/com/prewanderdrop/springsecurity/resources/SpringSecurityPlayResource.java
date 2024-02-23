package com.prewanderdrop.springsecurity.resources;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SpringSecurityPlayResource {

    @GetMapping("/csrf-token")
    public CsrfToken retrieveCsrfToken(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    }

    @Bean
    public UserDetailsService userDetailsService() {

        var user = User.withUsername("eleri")
        .password("{noop}eleri")
                .roles(String.valueOf(Role.USER))
                .build();

        var admin = User.withUsername("admin")
                .password("{noop}eleri")
                .roles(String.valueOf(Role.ADMIN))
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }
}

