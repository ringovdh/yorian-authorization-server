package be.yorian.controller;

import be.yorian.entity.OauthUser;
import be.yorian.entity.newUser;
import be.yorian.exception.InvalidUserException;
import be.yorian.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class RegistrationController {

    private final UserService userService;

    @Autowired
    public RegistrationController(UserService userService) {
        this.userService = userService;
    }


    @GetMapping("/registration")
    public String registrationForm(Model model) {
        model.addAttribute("user", new newUser("", "", ""));
        model.addAttribute("method", "post");
        return "registration";
    }

    @PostMapping("/register")
    public String register(@ModelAttribute newUser user) {
        try {
            userService.createUser(user);
            return "redirect:/login";
        } catch(InvalidUserException ex) {
            return "redirect:/registration";
        }
    }
}
