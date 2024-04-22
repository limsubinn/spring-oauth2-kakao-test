package com.example.kakaologin.oauth2.service;

import com.example.kakaologin.oauth2.model.OAuth2UserInfo;
import com.example.kakaologin.oauth2.model.OAuth2UserInfoFactory;
import com.example.kakaologin.oauth2.model.OAuth2UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2Service extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        log.info("[OauthService.loadUser]");

        // 기본 OAuth2UserService 객체 생성
        OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();

        // OAuth2UserService를 사용하여 OAuth2User 정보를 가져온다.
        OAuth2User oAuth2User = oAuth2UserService.loadUser(oAuth2UserRequest);

        // 클라이언트 등록 ID (google, kakao)
        String registrationId = oAuth2UserRequest
                .getClientRegistration()
                .getRegistrationId();

        // 액세스 토큰
        String accessToken = oAuth2UserRequest
                .getAccessToken()
                .getTokenValue();

        log.info("registrationId : {}", registrationId);
        log.info("accessToken : {}", accessToken);

        // 유저 정보
        OAuth2UserInfo oAuth2UserInfo =
                OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId,
                        accessToken,
                        oAuth2User.getAttributes());

        return OAuth2UserPrincipal.of(oAuth2UserInfo);
    }

}
