package in.theinsanetechie.springsecurity;

import in.theinsanetechie.springsecurity.repository.UserRepository;
import in.theinsanetechie.springsecurity.domain.User;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
@Slf4j
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository users;

    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        this.users.save(User.builder()
                .id(1001L)
                .username("admin")
                .password(this.passwordEncoder.encode("password"))
                .email("admin@theinsanetechie.in")
                .roles(Arrays.asList("ROLE_USER", "ROLE_ADMIN"))
                .build()
        );

        this.users.save(User.builder()
                .id(1002L)
                .username("user")
                .password(this.passwordEncoder.encode("password"))
                .email("user@theinsanetechie.in")
                .roles(Arrays.asList("ROLE_USER"))
                .build()
        );

        log.debug("printing all users...");
        this.users.findAll().forEach(v -> log.debug(" User :" + v.toString()));
    }
}

