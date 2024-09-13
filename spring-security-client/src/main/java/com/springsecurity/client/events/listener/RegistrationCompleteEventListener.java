package com.springsecurity.client.events.listener;

import com.springsecurity.client.entity.User;
import com.springsecurity.client.events.RegistrationCompleteEvent;
import com.springsecurity.client.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@Slf4j
public class RegistrationCompleteEventListener implements ApplicationListener<RegistrationCompleteEvent> {

    @Autowired
    private UserService userService;
    //
    @Override
    public void onApplicationEvent(RegistrationCompleteEvent event) {
        // Create token for user
        User user = event.getUser();
        String token = UUID.randomUUID().toString();
        userService.saveVerficationTokenForUser(token, user);

        String url = event.getApplicationUrl() + "/verifyRegistration?token="
                +token;
        // Send email verification code
 // http://localhost:8081/verifyRegistration?token=123123
        log.info("Click link " + url);
        // Email SMTP server
    }
}
