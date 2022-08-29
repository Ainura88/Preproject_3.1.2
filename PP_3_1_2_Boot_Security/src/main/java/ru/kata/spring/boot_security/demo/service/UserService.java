package ru.kata.spring.boot_security.demo.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import ru.kata.spring.boot_security.demo.model.User;

import java.util.List;

public interface UserService extends UserDetailsService {

    List<User> getUsers();

    void addUser(User user);

    void updateUserById(User user);

    void deleteUser(Long id);

    User getById(Long id);

    User getAuthUser();

}
