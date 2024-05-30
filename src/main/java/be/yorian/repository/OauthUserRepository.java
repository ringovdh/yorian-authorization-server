package be.yorian.repository;

import be.yorian.entity.OauthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OauthUserRepository extends JpaRepository<OauthUser, Integer> {

    Optional<OauthUser> findByEmail(String email);

}
