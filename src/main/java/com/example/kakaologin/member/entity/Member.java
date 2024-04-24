package com.example.kakaologin.member.entity;

import com.example.kakaologin.oauth2.model.OAuth2Provider;
import com.example.kakaologin.oauth2.model.OAuth2UserPrincipal;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id", nullable = false)
    private Long id;

    @Column(length = 50)
    private String email;

    @Column(length = 10)
    private String nickname;

    @Column
    private String profileImg;

    @Column(length = 20)
    private String phoneNumber;

    @Enumerated(EnumType.STRING)
    private OAuth2Provider socialType;

    @Builder
    private Member(String email, String nickname, String profileImg, String phoneNumber, OAuth2Provider socialType) {
        this.email = email;
        this.nickname = nickname;
        this.profileImg = profileImg;
        this.phoneNumber = phoneNumber;
        this.socialType = socialType;
    }

    public static Member from(OAuth2UserPrincipal principal) {
        return builder()
                .email(principal.getUserInfo().getEmail())
                .profileImg(principal.getUserInfo().getProfileImgUrl())
                .socialType(principal.getUserInfo().getProvider())
                .build();
    }

}
