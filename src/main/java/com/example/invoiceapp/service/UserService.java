package com.example.invoiceapp.service;

import com.example.invoiceapp.domain.User;
import com.example.invoiceapp.dto.UserDTO;

public interface UserService {
    UserDTO createUser(User user);
    UserDTO getUserByEmail(String email);

    void sendVerificationCode(UserDTO user);
}
