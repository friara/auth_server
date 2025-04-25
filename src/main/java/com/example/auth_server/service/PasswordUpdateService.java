package com.example.auth_server.service;

import com.example.auth_server.model.User;
import com.example.auth_server.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class PasswordUpdateService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Transactional
    public void updateAllPasswords() {
        // Получаем всех пользователей из базы данных
        List<User> users = userRepository.findAll();

        // Проходим по каждому пользователю и обновляем пароль
        for (User user : users) {
            // Хэшируем пароль
            String hashedPassword = passwordEncoder.encode(user.getPassword());

            // Обновляем пароль в объекте пользователя
            user.setPassword(hashedPassword);

            // Сохраняем обновленного пользователя в базе данных
            userRepository.save(user);
        }
    }
}

