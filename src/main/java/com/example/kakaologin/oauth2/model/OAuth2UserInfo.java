package com.example.kakaologin.oauth2.model;

public interface OAuth2UserInfo {

    OAuth2Provider getProvider();
    String getEmail();
    String getProfileImgUrl();

}
