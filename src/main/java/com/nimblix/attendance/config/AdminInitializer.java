package com.nimblix.attendance.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.nimblix.attendance.entity.Role;
import com.nimblix.attendance.entity.User;
import com.nimblix.attendance.repository.UserRepository;

@Component
public class AdminInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {

        if (!userRepository.existsByEmailIgnoreCase("admin@gmail.com")) {

            User admin = new User();
            admin.setEmail("admin@gmail.com");
            admin.setName("Affaq");
            admin.setPassword(passwordEncoder.encode("admin1234"));
            admin.setRole(Role.ADMIN);

            userRepository.save(admin);
            System.out.println("Admin user created");
        }
    }
}
