package com.example.kakaologin.refreshtoken.entity;

import lombok.Builder;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.io.Serializable;

@Getter
@RedisHash(value = "refreshToken", timeToLive = 60 * 60 * 24 * 7) // 7일
public class RefreshToken implements Serializable {

    @Id
    private String refreshToken;
    private Long memberId;
    private String role;

    @Builder
    private RefreshToken(String refreshToken, Long memberId, String role) {
        this.refreshToken = refreshToken;
        this.memberId = memberId;
        this.role = role;
    }

    public static RefreshToken of(String refreshToken, Long memberId, String role) {
        return builder()
                .refreshToken(refreshToken)
                .memberId(memberId)
                .role(role)
                .build();
    }

}
