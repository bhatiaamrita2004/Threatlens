package com.threatlens.backend.config;

import com.threatlens.backend.domain.AppUser;
import com.threatlens.backend.domain.Role;
import com.threatlens.backend.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Creates two demo users when the app starts: admin/admin123 and analyst/analyst123.
 * These passwords are for local development only. Turn this off with
 * threatlens.seed-demo-users=false.
 */
@Component
@ConditionalOnProperty(name = "threatlens.seed-demo-users", havingValue = "true")
public class DataSeeder implements CommandLineRunner {

    private final UserRepository users;
    private final PasswordEncoder encoder;

    public DataSeeder(UserRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
    }

    @Override
    public void run(String... args) {
        seed("admin", "admin123", Role.ADMIN);
        seed("analyst", "analyst123", Role.ANALYST);
    }

    private void seed(String username, String password, Role role) {
        if (!users.existsByUsername(username)) {
            users.save(new AppUser(username, encoder.encode(password), role));
        }
    }
}
