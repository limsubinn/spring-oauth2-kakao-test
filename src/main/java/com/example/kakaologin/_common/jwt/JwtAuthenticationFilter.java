package com.example.kakaologin._common.jwt;

import com.example.kakaologin._common.exception.BusinessException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.example.kakaologin._common.response.status.ErrorType.INVALID_TOKEN;
import static com.example.kakaologin._common.response.status.ErrorType.TOKEN_NOT_FOUND;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;

    private static final String TOKEN_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = getToken(request);

        // 만료된 토큰인지 확인
//        jwtUtils.isExpiredToken(token);

        // security context에 인증 정보 저장
        Authentication authentication = jwtUtils.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }

    private String getToken(HttpServletRequest request) {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        validateToken(token);
        return token.substring(TOKEN_PREFIX.length());
    }

    private void validateToken(String token) {
        if (!StringUtils.hasText(token)) {
            throw new BusinessException(TOKEN_NOT_FOUND);
        }
        if (!token.startsWith(TOKEN_PREFIX)) {
            throw new BusinessException(INVALID_TOKEN);
        }
    }

}