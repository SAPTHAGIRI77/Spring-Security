package com.springsecurity.client.controller;

import com.springsecurity.client.entity.User;
import com.springsecurity.client.entity.VerificationToken;
import com.springsecurity.client.events.RegistrationCompleteEvent;
import com.springsecurity.client.model.UserModel;
import com.springsecurity.client.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.web.bind.annotation.*;

@RestController
@Slf4j
public class UserRegistrationController {

    @Autowired
    private UserService userService;

    @Autowired
    private ApplicationEventPublisher publisher;


    @GetMapping("/ping")
    public String ping() {
        return "pong";
    }

    @PostMapping("/register")
    public String registerUser(@RequestBody UserModel userModel, final HttpServletRequest request) {
        User user = userService.registerUser(userModel);

        // Publish event for creating user
        publisher.publishEvent(new RegistrationCompleteEvent(user,
                applicationUrl(request)));
        // localhost:8080/verifytoken

        return "Success";
    }

    @GetMapping("/verifyRegistration")
    public String verifyRegistration(@RequestParam("token") String token) {

        String result = userService.validateVerificationToken(token);
        if (result.equalsIgnoreCase("valid")) {
            return "User Verfied Succefully";
        }

        return "Bad User";

    }

    @GetMapping("/resendVerifyToken")
    public String resendVerifyToken(@RequestParam("token") String oldToken,
                                    HttpServletRequest request) {

        VerificationToken verificationToken = userService.generateNewVerificationToken(oldToken);
        User user = verificationToken.getUser();

        // Send Email to User for user
        resendVerifyTokenMail(user,applicationUrl(request),verificationToken);
        return "Resend Verification Link sent";

    }

    private void resendVerifyTokenMail(User user, String applicationUrl, VerificationToken verificationToken) {
        String url = applicationUrl + "/resendVerifyToken?token="
                +verificationToken.getToken();

        log.info("Click API for verification "+ url);
    }

    private String applicationUrl(HttpServletRequest request) {
        return "http://" +
                request.getServerName() +
                ":" +
                request.getServerPort() +
                request.getContextPath();


    }
}
