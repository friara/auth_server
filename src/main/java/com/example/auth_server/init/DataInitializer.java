//package com.example.auth_server.init;
//
//import com.example.auth_server.model.Role;
//import com.example.auth_server.model.User;
//import com.example.auth_server.repository.UserRepository;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//
//import java.util.Arrays;
//
//@Component
//public class DataInitializer implements CommandLineRunner {
//
//    private final UserRepository userRepository;
//    private final PasswordEncoder passwordEncoder;
//
//    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
//        this.userRepository = userRepository;
//        this.passwordEncoder = passwordEncoder;
//    }
//
//    @Override
//    public void run(String... args) throws Exception {
//        // Создание пользователей
//        User user1 = new User();
//        user1.setLogin("user1");
//        user1.setPassword(passwordEncoder.encode("password1"));
//        user1.setRole(new Role("ROLE_USER"));
//        user1.setFirstName("FirstName1");
//        user1.setLastName("LastName1");
//
//        User user2 = new User();
//        user2.setLogin("user2");
//        user2.setPassword(passwordEncoder.encode("password2"));
//        user2.setRole("ADMIN");
//        user2.setFirstName("FirstName2");
//        user2.setLastName("LastName2");
//
//        // Сохранение пользователей в базу данных
//        userRepository.saveAll(Arrays.asList(user1, user2));
//    }
//}
//
