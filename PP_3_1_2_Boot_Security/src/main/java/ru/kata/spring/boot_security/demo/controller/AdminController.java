package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.UserService;

import java.util.List;

@Controller
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;

    @Autowired
    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @RequestMapping
    public String showAllUser(Model model) {
        List<User> allUsers = userService.getUsers();
        model.addAttribute("users", allUsers);
        return "users";
    }

    @RequestMapping("/add")
    public String add(Model model) {
        User user = new User();
        model.addAttribute("user", user);
        return "user-edit";
    }

    @RequestMapping(method = RequestMethod.POST, value = "/edit")
    public String createOrUpdateUser(@ModelAttribute User user) {
        userService.addUser(user);
        return "redirect:/admin";
    }

    @RequestMapping("/edit/{id}")
    public String editUser(@PathVariable(value = "id") Long id, Model model) {
        User user = userService.getById(id);
        model.addAttribute("user", user);
        return "user-edit";
    }

    @RequestMapping(value = "/delete/{id}")
    public String deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return "redirect:/admin";
    }
}
