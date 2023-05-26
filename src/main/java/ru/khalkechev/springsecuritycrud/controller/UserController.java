package ru.khalkechev.springsecuritycrud.controller;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.Errors;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import ru.khalkechev.springsecuritycrud.model.User;
import ru.khalkechev.springsecuritycrud.service.CustomUserDetailsService;
import ru.khalkechev.springsecuritycrud.service.UserService;
import ru.khalkechev.springsecuritycrud.util.UserValidator;

import java.security.Principal;

@Controller
@RequestMapping("/")
public class UserController {
    private final UserService userService;
    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final UserValidator userValidator;

    @Autowired
    public UserController(UserService userService, CustomUserDetailsService customUserDetailsService,
                          PasswordEncoder passwordEncoder, UserValidator userValidator) {
        this.userService = userService;
        this.customUserDetailsService = customUserDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.userValidator = userValidator;
    }

    @GetMapping("/admin")
    public String showList(Model model) {
        model.addAttribute("userList", userService.getListOfUsers());
        return "admin/index";
    }

    @GetMapping("/admin/new")
    public String showNewFormToAdd(@ModelAttribute("user") User user, Model model) {
        return "/admin/new";
    }

    @PostMapping("/admin")
    public String create(@ModelAttribute("user") @Valid User user, Errors errors) {
      //  userValidator.validate(user, errors);
        if (errors.hasErrors()) {
            return "/admin/new";
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userService.save(user);
        return "redirect:/admin";
    }

    @GetMapping("/admin/{id}/edit")
    public String edit(Model model, @PathVariable("id") long id) {
        model.addAttribute("user", userService.getUserById(id));
        model.addAttribute("userRoles", userService.getSetOfRoles());
        return "/admin/edit";
    }

    @PatchMapping("/admin/{id}")
    public String update(@ModelAttribute("user") @Valid User user, Errors errors,
                         @PathVariable("id") long id, Model model) {
        if (errors.hasErrors()) {
            model.addAttribute("userRoles", userService.getSetOfRoles());
            return "/admin/edit";
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userService.updateById(user, id);
        return "redirect:/admin";
    }

    @DeleteMapping("/admin/{id}")
    public String delete(@PathVariable("id") long id) {
        userService.deleteUserById(id);
        return "redirect:/admin";
    }

    @GetMapping("/user")
    public String getUserInfo(Model model, Principal principal) {
        User user = customUserDetailsService.findByUserName(principal.getName());
        model.addAttribute("user", user);
        return "user/showuser";
    }

}
