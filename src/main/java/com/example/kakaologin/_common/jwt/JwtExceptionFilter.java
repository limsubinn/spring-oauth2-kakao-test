package com.example.kakaologin._common.jwt;

import com.example.kakaologin._common.response.status.ErrorType;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static com.example.kakaologin._common.response.status.ErrorType.INVALID_TOKEN;
import static com.example.kakaologin._common.response.status.ErrorType.TOKEN_EXPIRED;

@Component
public class JwtExceptionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response); // 다음 필터로 넘기기
        } catch (ExpiredJwtException e) {
            setErrorResponse(response, TOKEN_EXPIRED);
        } catch (Exception e) {
            setErrorResponse(response, INVALID_TOKEN);
        }
    }

    public void setErrorResponse(HttpServletResponse response, ErrorType errorType) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> errors = new HashMap<>();
        errors.put("code", errorType.getHttpStatus().value());
        errors.put("status", errorType.getHttpStatus().name());
        errors.put("message", errorType.getMsg());

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writeValue(response.getOutputStream(), errors);
        response.setStatus(errorType.getHttpStatus().value());
    }

}
