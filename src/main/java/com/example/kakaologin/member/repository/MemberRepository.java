package com.example.kakaologin.member.repository;

import com.example.kakaologin.member.entity.Member;
import com.example.kakaologin.oauth2.model.OAuth2Provider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findBySocialTypeAndEmail(OAuth2Provider socialType, String email);

}
