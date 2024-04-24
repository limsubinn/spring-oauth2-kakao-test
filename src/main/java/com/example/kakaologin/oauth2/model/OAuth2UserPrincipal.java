package com.example.kakaologin.oauth2.model;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Getter
public class OAuth2UserPrincipal implements OAuth2User {

    private final OAuth2UserInfo userInfo;

    @Builder
    private OAuth2UserPrincipal(OAuth2UserInfo userInfo) {
        this.userInfo = userInfo;
    }

    public static OAuth2UserPrincipal of(OAuth2UserInfo userInfo) {
        return builder()
                .userInfo(userInfo)
                .build();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add((GrantedAuthority) () -> "CONSUMER");
        return collection;
    }

    @Override
    public String getName() {
        return userInfo.getEmail();
    }

}