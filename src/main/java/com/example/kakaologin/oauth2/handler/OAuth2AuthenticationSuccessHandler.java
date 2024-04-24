package com.example.kakaologin.oauth2.handler;

import com.example.kakaologin._common.utils.CookieUtils;
import com.example.kakaologin._common.utils.JwtUtils;
import com.example.kakaologin.member.entity.Member;
import com.example.kakaologin.member.service.MemberService;
import com.example.kakaologin.oauth2.model.OAuth2UserPrincipal;
import com.example.kakaologin.oauth2.repository.OAuth2AuthorizationRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

import static com.example.kakaologin.oauth2.repository.OAuth2AuthorizationRepository.MODE_PARAM_COOKIE_NAME;
import static com.example.kakaologin.oauth2.repository.OAuth2AuthorizationRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final OAuth2AuthorizationRepository oAuth2AuthorizationRepository;
    private final CookieUtils cookieUtils;
    private final JwtUtils jwtUtils;
    private final MemberService memberService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        // 이미 http 응답이 클라이언트로 보내진 경우
        if (response.isCommitted()) {
            return;
        }

        // 쿠키 삭제
        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, getTargetUrl(request, authentication));
    }

    private String getTargetUrl(HttpServletRequest request, Authentication authentication) {
        // redirect uri
        String redirectUri = getRedirectUriFromRequest(request);

        // login, logout, unlink
        String mode = getModeFromRequest(request);

        // 유저 인증 정보
        OAuth2UserPrincipal principal = getOAuth2UserPrincipal(authentication);
        if (principal == null) {
            return getFailUrl(redirectUri);
        }

        // 로그인
        if (mode.equals("login")) {
            // 회원 찾기
            Member member = memberService.getMemberOrNull(
                    principal.getUserInfo().getProvider(),
                    principal.getUserInfo().getEmail());

            // 로그인
            if (member != null) {
                return getLoginUrl(authentication, redirectUri, member.getId(), "login");
            }

            // 회원가입
            getLoginUrl(authentication, redirectUri, memberService.save(principal), "sign-up");
        }

        // TODO: 회원탈퇴, 로그아웃 로직 구현
        return getFailUrl(redirectUri);
    }

    private String getRedirectUriFromRequest(HttpServletRequest request) {
        return cookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue)
                .orElse("http://localhost:5173/login-callback");
    }

    private String getModeFromRequest(HttpServletRequest request) {
        return cookieUtils.getCookie(request, MODE_PARAM_COOKIE_NAME)
                .map(Cookie::getValue)
                .orElse(null);
    }

    private OAuth2UserPrincipal getOAuth2UserPrincipal(Authentication authentication) {
        Object principal = authentication.getPrincipal();

        if (principal instanceof OAuth2UserPrincipal) {
            return (OAuth2UserPrincipal) principal;
        }

        return null;
    }

    private String getFailUrl(String redirectUri) {
        return UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("error", "login-fail")
                .build().toUriString();
    }

    private String getLoginUrl(Authentication authentication, String redirectUri, Long memberId, String nextPage) {
        return UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("access-token", jwtUtils.generateAccessToken(authentication, memberId))
                .queryParam("refresh-token", jwtUtils.generateRefreshToken(authentication, memberId))
                .queryParam("next-page", nextPage)
                .build().toUriString();
    }

    private void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        oAuth2AuthorizationRepository.removeAuthorizationRequestCookies(request, response);
    }

}