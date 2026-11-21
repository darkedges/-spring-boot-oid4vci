package com.darkedges.bank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@org.springframework.scheduling.annotation.EnableScheduling
public class BankApplication {
    public static void main(String[] args) { SpringApplication.run(BankApplication.class, args); }
}
