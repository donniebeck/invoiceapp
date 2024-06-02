package com.example.invoiceapp.service.implementation;

import com.example.invoiceapp.domain.Role;
import com.example.invoiceapp.repository.RoleRepository;
import com.example.invoiceapp.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {
    private final RoleRepository<Role> roleRepository;
    @Override
    public Role getRoleByUserId(Long id) {
        return roleRepository.getRoleByUserId(id);
    }
}
