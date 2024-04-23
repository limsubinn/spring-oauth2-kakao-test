package com.example.kakaologin.member.service;

import com.example.kakaologin.member.entity.Member;
import com.example.kakaologin.member.repository.MemberRepository;
import com.example.kakaologin.oauth2.model.OAuth2Provider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
public class MemberService {

    private final MemberRepository memberRepository;

    public Member getMemberOrNull(OAuth2Provider socialType, String email) {
        return memberRepository.findBySocialTypeAndEmail(socialType, email)
                .orElse(null);
    }

}
