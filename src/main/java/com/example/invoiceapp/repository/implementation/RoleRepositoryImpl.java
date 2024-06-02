package com.example.invoiceapp.repository.implementation;

import com.example.invoiceapp.domain.Role;
import com.example.invoiceapp.exception.ApiException;
import com.example.invoiceapp.repository.RoleRepository;
import com.example.invoiceapp.rowmapper.RoleRowMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import static com.example.invoiceapp.enumeration.RoleType.ROLE_USER;
import static com.example.invoiceapp.query.RoleQuery.*;
import static java.util.Objects.requireNonNull;

@Repository
@RequiredArgsConstructor
@Slf4j
public class RoleRepositoryImpl implements RoleRepository<Role> {
    private final NamedParameterJdbcTemplate jdbc;

    @Override
    public Role create(Role data) {
        return null;
    }

    @Override
    public Collection<Role> list(int page, int pageSize) {
        return List.of();
    }

    @Override
    public Role get(Long id) {
        return null;
    }

    @Override
    public Role update(Role data) {
        return null;
    }

    @Override
    public void delete(Long id) {

    }

    @Override
    public void addRoleToUser(Long userId, String roleName) {
        log.info("Attempting to add role '{}' to user ID '{}'.", roleName, userId);

        try {
            log.debug("Fetching role '{}' from database.", roleName);
            Role role = jdbc.queryForObject(SELECT_ROLE_BY_NAME_QUERY, Map.of("name", roleName), new RoleRowMapper());

            if (role == null) {
                log.warn("No role found with name '{}'.", roleName);
            } else {
                log.debug("Role found: {}", role);
                log.debug("Updating user_roles table with user ID '{}' and role ID '{}'.", userId, role.getId());
                jdbc.update(INSERT_ROLE_TO_USER, Map.of("userId", userId, "roleId", requireNonNull(role).getId()));
                log.info("Role '{}' successfully added to user ID '{}'.", roleName, userId);
            }
        } catch (EmptyResultDataAccessException e) {
            log.error("No role found by name '{}': {}", roleName, e.getMessage());
            throw new ApiException("No role found by name: " + roleName);
        } catch (DataAccessException e) {
            log.error("Database access error when trying to add role to user: {}", e.getMessage());
            throw new ApiException("An error occurred while adding role to user: " + e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error occurred while adding role to user: {}", e.getMessage(), e);
            throw new ApiException("An unexpected error occurred while creating user: " + e.getMessage());
        }
    }

    @Override
    public Role getRoleByUserId(Long userId) {
        log.info("Fetching role for user id: {}", userId);
        try{
            return jdbc.queryForObject(SELECT_ROLE_BY_ID_QUERY, Map.of("id", userId), new RoleRowMapper());
        } catch (EmptyResultDataAccessException exception) {
            throw new ApiException("No role found by name " + ROLE_USER.name());
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new ApiException("An error occurred");
        }
    }

    @Override
    public Role getRoleByUserEmail(String email) {
        return null;
    }

    @Override
    public void updateUserRole(Long userId, String roleName) {

    }
}
