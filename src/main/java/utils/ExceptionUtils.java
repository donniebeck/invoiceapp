package utils;

import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.example.invoiceapp.domain.HttpResponse;
import com.example.invoiceapp.exception.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;

import java.io.OutputStream;

import static java.time.LocalTime.now;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
@Slf4j
public class ExceptionUtils {
    public static void processError(HttpServletResponse response, Exception e) {
        if(     e instanceof ApiException ||
                e instanceof BadCredentialsException ||
                e instanceof DisabledException ||
                e instanceof LockedException ||
                e instanceof InvalidClaimException ||
                e instanceof TokenExpiredException)
        {
            HttpResponse httpResponse = getHttpResponse(response, e.getMessage(), BAD_REQUEST);
            writeResponse(response, httpResponse);
        } else {
            HttpResponse httpResponse = getHttpResponse(response, "An error occurred. Please try again", INTERNAL_SERVER_ERROR);
            writeResponse(response, httpResponse);
        }
        log.error(e.getMessage());
    }

    private static void writeResponse(HttpServletResponse response, HttpResponse httpResponse) {
        OutputStream out;
        try{
            out = response.getOutputStream();
            ObjectMapper mapper = new ObjectMapper();
            mapper.writeValue(out, httpResponse);
            out.flush();
        }catch(Exception e) {
            log.error(e.getMessage());
        }
    }

    private static HttpResponse getHttpResponse(HttpServletResponse response, String message, HttpStatus httpStatus) {
        HttpResponse httpResponse = HttpResponse.builder()
                .timeStamp(now().toString())
                .reason(message)
                .status(httpStatus)
                .statusCode(UNAUTHORIZED.value())
                .build();
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(httpResponse.getStatusCode());
        return httpResponse;
    }
}
