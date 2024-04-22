package com.example.kakaologin.oauth2.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum OAuth2Provider {

    KAKAO("kakao"),
    ;

    private final String registrationId;

}
