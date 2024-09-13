package com.springsecurity.client.service;

import com.springsecurity.client.entity.User;
import com.springsecurity.client.entity.VerificationToken;
import com.springsecurity.client.model.UserModel;

public interface UserService {
    User registerUser(UserModel userModel);

    void saveVerficationTokenForUser(String token, User user);

    String validateVerificationToken(String token);



    VerificationToken generateNewVerificationToken(String oldToken);
}
