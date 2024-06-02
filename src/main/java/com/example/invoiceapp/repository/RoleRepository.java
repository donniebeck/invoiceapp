package com.example.invoiceapp.repository;

import com.example.invoiceapp.domain.Role;
import org.springframework.stereotype.Repository;

import java.util.Collection;

@Repository
public interface RoleRepository<T extends Role> {
    /* Basic CRUD Operations */
    T create(T data); //C
    Collection<T> list(int page, int pageSize); //R
    T get(Long id); //R
    T update(T data); //U
    void delete(Long id); //D

    /* More complex operations*/
    void addRoleToUser(Long userId, String roleName);
    Role getRoleByUserId(Long userId);
    Role getRoleByUserEmail(String email);
    void updateUserRole(Long userId, String roleName);
}
