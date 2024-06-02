package utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.AddressException;

public class SmsUtils {
    private static final Logger log = LoggerFactory.getLogger(SmsUtils.class);
    public static final String FROM_EMAIL = System.getenv("GMAIL_APP_ADDRESS");
    public static final String EMAIL_PASSWORD = System.getenv("GMAIL_APP_PASSWORD");
    public static final String SMTP_HOST = "smtp.gmail.com";
    public static final String SMTP_PORT = "587";

    public static void sendSMS(String toPhoneNumber, String messageBody) {
        // Check environment variables
        if (FROM_EMAIL == null || FROM_EMAIL.isEmpty()) {
            log.error("Environment variable GMAIL_APP_ADDRESS is not set or empty.");
            throw new IllegalArgumentException("Environment variable GMAIL_APP_ADDRESS is not set or empty.");
        }

        if (EMAIL_PASSWORD == null || EMAIL_PASSWORD.isEmpty()) {
            log.error("Environment variable GMAIL_APP_PASSWORD is not set or empty.");
            throw new IllegalArgumentException("Environment variable GMAIL_APP_PASSWORD is not set or empty.");
        }

        // Check recipient phone number
        if (toPhoneNumber == null || toPhoneNumber.isEmpty()) {
            log.error("Recipient phone number is null or empty.");
            throw new IllegalArgumentException("Recipient phone number is null or empty.");
        }

        String toEmail = toPhoneNumber + "@mms.att.net"; // AT&T SMS gateway
        log.debug("Sending SMS to: " + toEmail);

        // Set up email properties
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", SMTP_HOST);
        props.put("mail.smtp.port", SMTP_PORT);

        // Create a session with an authenticator
        Session session = Session.getInstance(props, new javax.mail.Authenticator() {
            protected javax.mail.PasswordAuthentication getPasswordAuthentication() {
                return new javax.mail.PasswordAuthentication(FROM_EMAIL, EMAIL_PASSWORD);
            }
        });

        try {
            // Create a MimeMessage
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(FROM_EMAIL));

            // Validate and set recipient email address
            try {
                InternetAddress[] recipientAddresses = InternetAddress.parse(toEmail, true);
                message.setRecipients(Message.RecipientType.TO, recipientAddresses);
            } catch (AddressException e) {
                log.error("Invalid email address format: " + toEmail, e);
                throw new RuntimeException("Invalid email address format: " + toEmail, e);
            }

            message.setSubject(""); // SMS messages do not require a subject
            message.setText(messageBody);

            // Send the message
            Transport.send(message);

            log.info("Message sent successfully to " + toPhoneNumber);
        } catch (MessagingException e) {
            log.error("Error sending SMS: " + e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }
}
