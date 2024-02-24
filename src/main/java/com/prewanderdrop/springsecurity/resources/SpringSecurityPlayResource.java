package com.prewanderdrop.springsecurity.resources;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;

@RestController
public class SpringSecurityPlayResource {

    @GetMapping("/csrf-token")
    public CsrfToken retrieveCsrfToken(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//
//        var user = User.withUsername("eleri")
//        .password("{noop}eleri")
//                .roles(String.valueOf(Role.USER))
//                .build();
//
//        var admin = User.withUsername("admin")
//                .password("{noop}eleri")
//                .roles(String.valueOf(Role.ADMIN))
//                .build();
//
//        return new InMemoryUserDetailsManager(user, admin);
//    }

    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    // Insert the users into the database
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {

        var user = User.withUsername("eleri")
//        .password("{noop}eleri")
                .password("eleri")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles(String.valueOf(Role.USER))
                .build();

        var admin = User.withUsername("admin")
//                .password("{noop}eleri")
                .password("eleri")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles(String.valueOf(Role.ADMIN))
                .build();

        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}

