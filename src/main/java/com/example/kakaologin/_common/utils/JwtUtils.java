package com.example.kakaologin._common.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtUtils {

    private final long ACCESS_TOKEN_VALID_TIME = (60 * 1000) * 30; // 30분
//    private final long REFRESH_TOKEN_VALID_TIME = (60 * 1000) * 60 * 24 * 7; // 7일
    private final String AUTHORITIES_KEY = "role";

    @Value("${secret.jwt-secret-key}")
    private String JWT_SECRET_KEY;
    private Key key;

    @PostConstruct
    protected void init() {
        String encodedKey = Base64.getEncoder().encodeToString(JWT_SECRET_KEY.getBytes());
        this.key = Keys.hmacShaKeyFor(encodedKey.getBytes()); // JWT_SECRET_KEY -> Key
    }

    public String generateAccessToken(Authentication authentication, Long memberId) {
        return generateToken(authentication, memberId, ACCESS_TOKEN_VALID_TIME);
    }

    private String generateToken(Authentication authentication, Long memberId, long validTime) {
        log.info("[JwtUtils.generateToken]");

        // 권한
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst().orElseGet(null);

        // 현재 날짜
        Date now = new Date();
        // 만료 날짜
        Date expiration = new Date(now.getTime() + validTime);

        return Jwts.builder()
                .setSubject(memberId.toString())
                .claim(AUTHORITIES_KEY, authorities)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

//    public boolean isExpiredToken(String token) {
//        return getClaims(token).getExpiration().before(new Date());
//    }

    public Authentication getAuthentication(String token) {
        log.info("[JwtUtils.getAuthentication]");

        Claims claims = getClaims(token);

        // 권한
        String authorities = claims.get(AUTHORITIES_KEY, String.class);
        List<GrantedAuthority> authList = new ArrayList<>();
        authList.add(new SimpleGrantedAuthority(authorities));

        User user = new User(claims.getSubject(), "", authList);
        return new UsernamePasswordAuthenticationToken(user, token, authList);
    }

    public Long getMemberId(String token) {
        Claims claims = getClaims(token);
        return Long.parseLong(claims.getSubject());
    }

    public String getRole(String token) {
        return getClaims(token).get(AUTHORITIES_KEY, String.class);
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

}