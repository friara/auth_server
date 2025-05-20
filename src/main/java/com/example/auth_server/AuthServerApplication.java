package com.example.auth_server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.time.ZoneId;
import java.util.TimeZone;

@SpringBootApplication
public class AuthServerApplication {

	public static void main(String[] args) {
		TimeZone.setDefault(TimeZone.getTimeZone("UTC")); // Принудительная установка UTC
		System.out.println("Часовой пояс JVM: " + ZoneId.systemDefault());
		SpringApplication.run(AuthServerApplication.class, args);
	}

}
