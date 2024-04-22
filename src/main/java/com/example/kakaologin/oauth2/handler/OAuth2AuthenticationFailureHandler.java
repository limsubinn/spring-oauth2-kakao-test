package com.example.kakaologin.oauth2.handler;

import com.example.kakaologin._common.exception.BusinessException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import static com.example.kakaologin._common.response.status.ErrorType.OAUTH_AUTHENTICATION_FAIL;

@Component
@Slf4j
public class OAuth2AuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        // 인증 실패
        log.error("oauth2 인증 실패 : {}", exception.getMessage());
        throw new BusinessException(OAUTH_AUTHENTICATION_FAIL);
    }

}