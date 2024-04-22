package com.example.kakaologin.oauth2.model;

import lombok.Builder;

import java.util.Map;

public class KakaoOAuth2UserInfo implements OAuth2UserInfo {

    private OAuth2Provider provider;
    private String id;
    private String email;
    private String profileImgUrl;
    private String accessToken;

    @Builder
    private KakaoOAuth2UserInfo(OAuth2Provider provider, String id, String email, String profileImgUrl, String accessToken) {
        this.provider = provider;
        this.id = id;
        this.email = email;
        this.profileImgUrl = profileImgUrl;
        this.accessToken = accessToken;
    }

    public static KakaoOAuth2UserInfo of(Map<String, Object> attributes, String accessToken) {
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> kakaoProfile = (Map<String, Object>) kakaoAccount.get("profile");

        return builder()
                .provider(OAuth2Provider.KAKAO)
                .id(((Long) attributes.get("id")).toString())
                .email((String) kakaoAccount.get("email"))
                .profileImgUrl((String) kakaoProfile.get("profile_image_url"))
                .accessToken(accessToken)
                .build();
    }

    @Override
    public OAuth2Provider getProvider() {
        return provider;
    }

    @Override
    public String getAccessToken() {
        return accessToken;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public String profileImgUrl() {
        return profileImgUrl;
    }
    
}