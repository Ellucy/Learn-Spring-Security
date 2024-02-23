package com.prewanderdrop.springsecurity.resources;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class TodoResource {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    public static final List<Todo> TODOS = List.of(new Todo("eleri", "Learn Spring Security"),
            new Todo("eleri", "Get AWS Certificate"));

    @GetMapping("/todos")
    public List<Todo> retrieveTodos() {
        return TODOS;
    }

    // Annotation indicates that the method handles GET requests for the specified URL pattern
    @GetMapping("users/{username}/todos")

    // Annotation is used to indicate that the username parameter of the method should be bound to the value extracted from the URL path variable {username}
    public Todo retrieveTodosForASpecificUser(@PathVariable String username) {
        return TODOS.get(0);
    }

    @PostMapping("users/{username}/todos")
    public void createTodoForASpecificUser(@PathVariable String username, @RequestBody Todo todo) {
        logger.info("Create {} for {}", todo, username);
    }

}

record Todo (String username, String description ) {}