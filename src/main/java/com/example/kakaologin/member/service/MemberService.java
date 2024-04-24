package com.example.kakaologin.member.service;

import com.example.kakaologin.member.entity.Member;
import com.example.kakaologin.member.repository.MemberRepository;
import com.example.kakaologin.oauth2.model.OAuth2Provider;
import com.example.kakaologin.oauth2.model.OAuth2UserPrincipal;
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

    @Transactional
    public Long save(OAuth2UserPrincipal principal) {
        Member member = Member.from(principal);
        memberRepository.save(member);
        return member.getId();
    }

    public Member getMemberOrNull(OAuth2Provider socialType, String email) {
        return memberRepository.findBySocialTypeAndEmail(socialType, email)
                .orElse(null);
    }

}
