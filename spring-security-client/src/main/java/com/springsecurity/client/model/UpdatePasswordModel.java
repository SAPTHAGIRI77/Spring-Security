package com.springsecurity.client.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdatePasswordModel {

    @Email
    private String email;
    @NotNull
    private String oldPassword;
    @NotNull
    private String newPassword;

}
