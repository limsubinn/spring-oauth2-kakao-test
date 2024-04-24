package com.example.kakaologin.oauth2.handler;

import com.example.kakaologin._common.utils.CookieUtils;
import com.example.kakaologin.oauth2.repository.OAuth2AuthorizationRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

import static com.example.kakaologin.oauth2.repository.OAuth2AuthorizationRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final OAuth2AuthorizationRepository oAuth2AuthorizationRepository;
    private final CookieUtils cookieUtils;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        log.error("oauth2 인증 실패 : {}", exception.getMessage());

        // redirect uri
        String targetUrl = UriComponentsBuilder.fromUriString(getRedirectUriFromRequest(request))
                .queryParam("error", exception.getLocalizedMessage())
                .build().toUriString();

        // 쿠키 삭제
        oAuth2AuthorizationRepository.removeAuthorizationRequestCookies(request, response);

        // 리다이렉트
        response.sendRedirect(targetUrl);
    }

    private String getRedirectUriFromRequest(HttpServletRequest request) {
        return cookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue)
                .orElse("http://localhost:5173/login-callback");
    }

}