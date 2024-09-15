package com.springsecurity.client.service;

import com.springsecurity.client.entity.User;
import com.springsecurity.client.entity.VerificationToken;
import com.springsecurity.client.model.UpdatePasswordModel;
import com.springsecurity.client.model.UserModel;
import com.springsecurity.client.repository.UserRepository;
import com.springsecurity.client.repository.VerificationTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private VerificationTokenRepository verificationTokenRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public User registerUser(UserModel userModel) {
       User user = new User();
       user.setFirstName(userModel.getFirstName());
       user.setLastName(userModel.getLastName());
       user.setEmail(userModel.getEmail());
       user.setPassword(passwordEncoder.encode(userModel.getPassword()));
       user.setRole("USER");
       userRepository.save(user);
       return user;

    }

    @Override
    public void saveVerficationTokenForUser(String token, User user) {

        VerificationToken verificationToken = new VerificationToken(user, token);
        verificationTokenRepository.save(verificationToken);
        // Send email from her

    }

    @Override
    public String validateVerificationToken(String token) {
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token);
        if(verificationToken ==null){
            return "invalid";
        }

        User user = verificationToken.getUser();
        Calendar cal = Calendar.getInstance(); // current time

        if((verificationToken.getExpirationTime().getTime() - cal.getTime().getTime() <= 0)){
            verificationTokenRepository.delete(verificationToken);
            return "expired";
        }

        user.setEnabled(true);
        userRepository.save(user);
        return "valid";

    }

    @Override
    public VerificationToken generateNewVerificationToken(String oldToken) {
        VerificationToken verifyToken = verificationTokenRepository.findByToken(oldToken);
        verifyToken.setToken(UUID.randomUUID().toString());
        verificationTokenRepository.save(verifyToken);
        return verifyToken;

    }


    public String updatePassword(UpdatePasswordModel updatePasswordModel) {
        User user = userRepository.findByEmail(updatePasswordModel.getEmail());

        if (user != null) {

            if (passwordEncoder.matches(updatePasswordModel.getOldPassword(), user.getPassword())
                    && user.getEmail().equalsIgnoreCase(updatePasswordModel.getEmail())) {

                user.setPassword(passwordEncoder.encode(updatePasswordModel.getNewPassword()));
                userRepository.save(user);
                return "Password Updated successfully";
            }
        }

        return "Enter a Valid Email or Password";
    }

}
