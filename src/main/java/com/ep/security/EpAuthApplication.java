package com.ep.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class EpAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(EpAuthApplication.class, args);
    }

}
