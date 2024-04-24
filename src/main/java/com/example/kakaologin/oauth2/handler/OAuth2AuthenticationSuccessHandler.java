package com.example.kakaologin.oauth2.handler;

import com.example.kakaologin._common.utils.CookieUtils;
import com.example.kakaologin._common.utils.JwtUtils;
import com.example.kakaologin.member.entity.Member;
import com.example.kakaologin.member.service.MemberService;
import com.example.kakaologin.oauth2.model.OAuth2UserPrincipal;
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

    private final CookieUtils cookieUtils;
    private final JwtUtils jwtUtils;
    private final MemberService memberService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {


    }

    private String getTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                  Authentication authentication) {
        // redirect uri
        String redirectUri = getRedirectUriFromRequest(request);

        // mode
        String mode = getModeFromRequest(request); // login, logout, unlink
        if (mode == null) {
            return getFailUrl(redirectUri);
        }

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

            Long memberId;
            String nextPage = "";

            if (member != null) {
                // 로그인
                memberId = member.getId();
                nextPage = "login";
            }
            else {
                // 회원가입
                memberId = memberService.save(principal);
                nextPage = "sign-up";
            }

            // 회원가입 or 로그인 페이지로 리다이렉트
            return UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam("access-token", jwtUtils.generateAccessToken(authentication, memberId))
                    .queryParam("refresh-token", jwtUtils.generateRefreshToken(authentication, memberId))
                    .queryParam("next-page", nextPage)
                    .build().toUriString();
        }

        // TODO: 회원탈퇴, 로그아웃 로직 구현
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

}