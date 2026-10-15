package com.tablebooking.service;

import com.tablebooking.dto.UserLoginRequest;
import com.tablebooking.dto.UserRegisterRequest;
import com.tablebooking.entity.User;
import com.tablebooking.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UserServiceTest {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private UserService userService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        passwordEncoder = new BCryptPasswordEncoder();
        userService = new UserService(userRepository, passwordEncoder);
    }

    @Test
    void storesRegisteredPasswordAsBcryptHash() {
        when(userRepository.existsByEmailIgnoreCase("person@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        userService.register(new UserRegisterRequest("Person", "person@example.com", "password123", "1234567890"));

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        String storedPassword = userCaptor.getValue().getPassword();
        assertThat(storedPassword).isNotEqualTo("password123");
        assertThat(passwordEncoder.matches("password123", storedPassword)).isTrue();
    }

    @Test
    void logsInWhenPasswordMatchesBcryptHash() {
        User user = new User();
        user.setName("Person");
        user.setEmail("person@example.com");
        user.setPassword(passwordEncoder.encode("password123"));
        user.setPhone("1234567890");
        when(userRepository.findByEmailIgnoreCase("person@example.com")).thenReturn(Optional.of(user));

        var response = userService.login(new UserLoginRequest("person@example.com", "password123"));

        assertThat(response.email()).isEqualTo("person@example.com");
    }
}