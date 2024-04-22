package com.example.kakaologin.member.entity;

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
    private SocialType socialType;

    @Builder
    private Member(String email, String nickname, String profileImg, String phoneNumber, SocialType socialType) {
        this.email = email;
        this.nickname = nickname;
        this.profileImg = profileImg;
        this.phoneNumber = phoneNumber;
        this.socialType = socialType;
    }

}
