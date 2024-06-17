package com.example.invoiceapp.repository.implementation;


import com.example.invoiceapp.domain.Role;
import com.example.invoiceapp.domain.User;
import com.example.invoiceapp.domain.UserPrincipal;
import com.example.invoiceapp.dto.UserDTO;
import com.example.invoiceapp.exception.ApiException;
import com.example.invoiceapp.repository.RoleRepository;
import com.example.invoiceapp.repository.UserRepository;
import com.example.invoiceapp.rowmapper.UserRowMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.*;

import static com.example.invoiceapp.enumeration.RoleType.ROLE_USER;
import static com.example.invoiceapp.enumeration.VerificationType.ACCOUNT;
import static com.example.invoiceapp.query.UserQuery.*;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.apache.commons.lang3.time.DateFormatUtils.format;
import static org.apache.commons.lang3.time.DateUtils.addDays;

@Repository
@RequiredArgsConstructor
@Slf4j
public class UserRepositoryImpl implements UserRepository<User>, UserDetailsService {

    private static final String DATE_FORMAT = "yyyy-MM-dd hh:mm:ss";
    private final NamedParameterJdbcTemplate jdbc;
    private final RoleRepository<Role> roleRepository;
    private final BCryptPasswordEncoder encoder;

    @Override
    public User create(User user) {
        // Check the email is unique
        if (getEmailCount(user.getEmail().trim().toLowerCase()) > 0)
            throw new ApiException("Email already in use. Please try another.");
        // Save new user
        try {
            KeyHolder holder = new GeneratedKeyHolder();
            SqlParameterSource parameters = getSqlParameterSource(user);
            jdbc.update(INSERT_USER_QUERY, parameters, holder);
            user.setId(Objects.requireNonNull(holder.getKey()).longValue());
            // Add role to user
            roleRepository.addRoleToUser(user.getId(), ROLE_USER.name());
            // Send verification url
            log.info("Role assigned, proceeding to save verification URL.");
            String verificationUrl = getVerificationUrl(UUID.randomUUID().toString(), ACCOUNT.getType());
            // Save url in verification table
            log.info("Verification URL saved, proceeding to send email.");
            jdbc.update(INSERT_ACCOUNT_VERIFICATION_URL_QUERY, Map.of("userId", user.getId(), "url", verificationUrl));
            // Send email to user with url
            //emailService.sendVerificationURL(user.getFirstName(), user.getEmail(), verificationUrl, ACCOUNT);
            user.setEnabled(false);
            user.setNotLocked(true);
            // Return the new user
            return user;
            // if any errors, throw exception with msg
        } catch (Exception e) {
            throw new ApiException(e.getMessage());
        }
    }

    @Override
    public Collection<User> list(int page, int pageSize) {
        return List.of();
    }

    @Override
    public User get(Long id) {
        return null;
    }

    @Override
    public User update(User data) {
        return null;
    }

    @Override
    public void delete(Long id) {

    }

    private Integer getEmailCount(String email) {
        return jdbc.queryForObject(COUNT_USER_EMAIL_QUERY, Map.of("email", email), Integer.class);
    }
    private SqlParameterSource getSqlParameterSource(User user) {
        return new MapSqlParameterSource()
                .addValue("firstName", user.getFirstName())
                .addValue("lastName", user.getLastName())
                .addValue("email", user.getEmail())
                .addValue("password", encoder.encode(user.getPassword()));
    }
    private String getVerificationUrl(String key, String type) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/verify" + type + "/" + key).toUriString();
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = getUserByEmail(email);
        if(user == null) {
            log.error("User not found");
            throw new UsernameNotFoundException("User not found");
        } else {
            log.info("User found {}", email);
            return new UserPrincipal(user, roleRepository.getRoleByUserId(user.getId()));
        }
    }

    @Override
    public User getUserByEmail(String email) {
        try {
            return jdbc.queryForObject(SELECT_USER_BY_EMAIL_QUERY, Map.of("email", email), new UserRowMapper());
        } catch (EmptyResultDataAccessException e) {
            throw new ApiException("No user found by email: " + email);
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new ApiException("An error occurred.");
        }
    }

    @Override
    public void sendVerificationCode(UserDTO user) {
        String expirationDate = format(addDays(new Date(), 1), DATE_FORMAT);
        String verificationCode = randomAlphabetic(8).toUpperCase();
        try {
            // Log the user information
            log.debug("User ID: " + user.getId());
            log.debug("User Phone: " + user.getPhone());

            // Check if phone number is null
            if (user.getPhone() == null || user.getPhone().isEmpty()) {
                throw new ApiException("User phone number is null or empty.");
            }

            // Execute database updates
            jdbc.update(DELETE_VERIFICATION_CODE_BY_USER_ID, Map.of("id", user.getId()));
            jdbc.update(INSERT_VERIFICATION_CODE_QUERY, Map.of("userId", user.getId(), "code", verificationCode, "expirationDate", expirationDate));

            // Log the verification code
            log.debug("Verification Code: " + verificationCode);

            // Send SMS
            //sendSMS(user.getPhone(), "From: DonnieInvoiceApp \nVerification Code\n" + verificationCode);
            log.info("Verification Code: " + verificationCode);
        } catch (Exception e) {
            log.error("Error sending verification code: " + e.getMessage(), e);
            throw new ApiException("An error occurred.");
        }
    }

    @Override
    public User verifyCode(String email, String code) {
        if(isVerificationCodeExpired(code)) throw new ApiException("Verification code expired.");
        try {
            User userByCode = jdbc.queryForObject(SELECT_USER_BY_USER_CODE_QUERY, Map.of("code", code), new UserRowMapper());
            User userByEmail = jdbc.queryForObject(SELECT_USER_BY_EMAIL_QUERY,  Map.of("email", email), new UserRowMapper());
            if (userByCode.getEmail().equals(userByEmail.getEmail())) {
                jdbc.update(DELETE_CODE, Map.of("code", code));
                return userByCode;
            } else {
                throw new ApiException("Code is invalid. Please try again.");
            }
        } catch (EmptyResultDataAccessException e) {
            throw new ApiException("Unable to find record");
        } catch (Exception e) {
            throw new ApiException("An error occurred. Please try again.");
        }
    }

    private Boolean isVerificationCodeExpired(String code) {
        try {
            return jdbc.queryForObject(SELECT_CODE_EXPIRATION_QUERY, Map.of("code", code) , Boolean.class);
        }  catch (EmptyResultDataAccessException e) {
            throw new ApiException("Code not valid. Please try again.");
        } catch (Exception e) {
            throw new ApiException("An error occurred. Please try again.");
        }
    }
}