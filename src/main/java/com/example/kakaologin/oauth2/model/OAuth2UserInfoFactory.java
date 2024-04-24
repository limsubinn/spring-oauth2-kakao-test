package com.example.kakaologin.oauth2.model;

import com.example.kakaologin._common.exception.BusinessException;

import java.util.Map;

import static com.example.kakaologin._common.response.status.ErrorType.PROVIDER_NOT_SUPPORTED;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId,
                                                   Map<String, Object> attributes) {

        if (OAuth2Provider.KAKAO.getRegistrationId().equals(registrationId)) {
            return KakaoOAuth2UserInfo.of(attributes);
        }

        throw new BusinessException(PROVIDER_NOT_SUPPORTED);
    }
}