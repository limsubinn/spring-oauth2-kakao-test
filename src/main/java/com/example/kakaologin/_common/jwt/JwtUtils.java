package com.example.kakaologin._common.jwt;

import com.example.kakaologin._common.exception.BusinessException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Collectors;

import static com.example.kakaologin._common.response.status.ErrorType.INVALID_TOKEN;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtUtils implements InitializingBean {

    private final long ACCESS_TOKEN_VALID_TIME = (60 * 1000) * 30; // 30분
//    private final long REFRESH_TOKEN_VALID_TIME = (60 * 1000) * 60 * 24 * 7; // 7일
    private final String AUTHORITIES_KEY = "role";

    @Value("${secret.jwt-secret-key}")
    private String JWT_SECRET_KEY;
    private Key key;

    @PostConstruct
    protected void init() {
        String encodedKey = Base64.getEncoder().encodeToString(JWT_SECRET_KEY.getBytes());
        key = Keys.hmacShaKeyFor(encodedKey.getBytes());
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        this.key = Keys.hmacShaKeyFor(JWT_SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Authentication authentication, Long memberId) {
        return generateToken(authentication, memberId);
    }

    private String generateToken(Authentication authentication, Long memberId) {
        // 권한
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining());

        // 현재 날짜
        Date now = new Date();
        // 만료 날짜
        Date expiration = new Date(now.getTime() + ACCESS_TOKEN_VALID_TIME);

        return Jwts.builder()
                .setSubject(memberId.toString())
                .claim(AUTHORITIES_KEY, authorities)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isExpiredToken(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    public Long getMemberId(String token) {
        Claims claims = getClaims(token);
        return Long.parseLong(claims.getSubject());
    }

    public String getRole(String token) {
        return getClaims(token).get(AUTHORITIES_KEY, String.class);
    }

    private Claims getClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            throw new BusinessException(INVALID_TOKEN);
        }
    }

}