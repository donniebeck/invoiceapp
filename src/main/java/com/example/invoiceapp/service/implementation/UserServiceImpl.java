package com.example.invoiceapp.service.implementation;

import com.example.invoiceapp.domain.Role;
import com.example.invoiceapp.domain.User;
import com.example.invoiceapp.dto.UserDTO;
import com.example.invoiceapp.repository.RoleRepository;
import com.example.invoiceapp.repository.UserRepository;
import com.example.invoiceapp.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import static com.example.invoiceapp.dtomapper.UserDTOMapper.fromUser;

@Service
@RequiredArgsConstructor
public class UserServiceImpl  implements UserService {
    private final UserRepository<User> userRepository;
    private final RoleRepository<Role> roleRepository;

    @Override
    public UserDTO createUser(User user) {
        return mapToUserDTO(userRepository.create(user));
    }

    @Override
    public UserDTO getUserByEmail(String email) {
        return mapToUserDTO(userRepository.getUserByEmail(email));
    }

    @Override
    public void sendVerificationCode(UserDTO user) {
        userRepository.sendVerificationCode(user);
    }

    @Override
    public UserDTO verifyCode(String email, String code) {
        return mapToUserDTO(userRepository.verifyCode(email, code));
    }

    @Override
    public void resetPassword(String email) {
        userRepository.resetPassword(email);
    }

    @Override
    public UserDTO verifyPasswordKey(String key) {
        return mapToUserDTO(userRepository.verifyPasswordKey(key));
    }

    @Override
    public void renewPassword(String key, String password, String confirmPassword) {
        userRepository.renewPassword(key, password, confirmPassword);
    }

    private UserDTO mapToUserDTO(User user) {
        return fromUser(user, roleRepository.getRoleByUserId(user.getId()));
    }

}
