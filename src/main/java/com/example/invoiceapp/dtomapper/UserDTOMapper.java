package com.example.invoiceapp.dtomapper;

import com.example.invoiceapp.domain.Role;
import com.example.invoiceapp.domain.User;
import com.example.invoiceapp.dto.UserDTO;
import org.springframework.beans.BeanUtils;


public class UserDTOMapper {
    public static UserDTO fromUser(User user) {
        UserDTO userDTO = new UserDTO();
        BeanUtils.copyProperties(user, userDTO);
        return userDTO;
    }
    public static UserDTO fromUser(User user, Role role) {
        UserDTO userDTO = new UserDTO();
        BeanUtils.copyProperties(user, userDTO);
        userDTO.setRoleName(role.getName());
        userDTO.setPermissions(role.getPermission());
        return userDTO;
    }
    public static User toUser(UserDTO userDTO) {
        User user = new User();
        BeanUtils.copyProperties(userDTO, user);
        return user;
    }

}
