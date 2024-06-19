package com.example.invoiceapp.repository;

import com.example.invoiceapp.domain.User;
import com.example.invoiceapp.dto.UserDTO;

import java.util.Collection;

public interface UserRepository<T extends User> {
    /* Basic CRUD Operations */
    T create(T data); //C
    Collection<T> list(int page, int pageSize); //R
    T get(Long id); //R
    T update(T data); //U
    void delete(Long id); //D

    /* More complex operations*/
    User getUserByEmail(String email);

    void sendVerificationCode(UserDTO user);

    User verifyCode(String email, String code);

    void resetPassword(String email);

    User verifyPasswordKey(String key);

    void renewPassword(String key, String password, String confirmPassword);

    T verifyAccountKey(String key);
}
