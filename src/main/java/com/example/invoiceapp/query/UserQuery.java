package com.example.invoiceapp.query;

public class UserQuery {
    public static final String INSERT_USER_QUERY =
            "INSERT INTO users (first_name, last_name, email, password) VALUES (:firstName, :lastName, :email, :password)";

    public static final String COUNT_USER_EMAIL_QUERY = "SELECT COUNT(*) FROM users WHERE email = :email";

    public static final String INSERT_ACCOUNT_VERIFICATION_URL_QUERY = "INSERT INTO account_verifications (user_id, url) VALUES (:userId, :url)";

    public static final String SELECT_USER_BY_EMAIL_QUERY = "SELECT * FROM users WHERE email = :email";

    public static final String SELECT_USER_BY_USER_CODE_QUERY = "SELECT * FROM users WHERE id = (SELECT user_id FROM two_factor_verifications WHERE code = :code)";

    public static final String DELETE_VERIFICATION_CODE_BY_USER_ID = "DELETE FROM two_factor_verifications WHERE user_id = :id";

    public static final String DELETE_CODE = "DELETE FROM two_factor_verifications WHERE code = :code";

    public static final String INSERT_VERIFICATION_CODE_QUERY = "INSERT INTO two_factor_verifications (user_id, code, expiration_date) VALUES (:userId, :code, :expirationDate)";

    public static final String SELECT_CODE_EXPIRATION_QUERY = "SELECT expiration_date < NOW() AS is_expired FROM two_factor_verifications WHERE code = :code";
}
