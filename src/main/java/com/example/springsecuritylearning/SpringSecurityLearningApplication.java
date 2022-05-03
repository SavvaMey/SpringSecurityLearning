package com.example.springsecuritylearning;

import com.example.springsecuritylearning.security.ApplicationUserPermission;
import com.example.springsecuritylearning.security.ApplicationUserRole;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import java.util.Set;

@SpringBootApplication
@EnableConfigurationProperties
public class SpringSecurityLearningApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityLearningApplication.class, args);
    }

}
