package com.example.invoiceapp.service.implementation;

import com.example.invoiceapp.domain.User;
import com.example.invoiceapp.dto.UserDTO;
import com.example.invoiceapp.dtomapper.UserDTOMapper;
import com.example.invoiceapp.repository.UserRepository;
import com.example.invoiceapp.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import static com.example.invoiceapp.dtomapper.UserDTOMapper.fromUser;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository<User> userRepository;

    @Override
    public UserDTO createUser(User user) {
        return fromUser(userRepository.create(user));
    }

    @Override
    public UserDTO getUserByEmail(String email) {
        return UserDTOMapper.fromUser(userRepository.getUserByEmail(email));
    }

    @Override
    public void sendVerificationCode(UserDTO user) {
        userRepository.sendVerificationCode(user);
    }

}
