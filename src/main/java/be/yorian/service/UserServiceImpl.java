package be.yorian.service;

import be.yorian.entity.OauthUser;
import be.yorian.entity.newUser;
import be.yorian.exception.InvalidUserException;
import be.yorian.repository.OauthUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class UserServiceImpl implements UserService {

    private final OauthUserRepository oauthUserRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(OauthUserRepository oauthUserRepository,
                           PasswordEncoder passwordEncoder) {
        this.oauthUserRepository = oauthUserRepository;
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public OauthUser createUser(newUser user) {
        validatePassword(user);
        validateUser(user);
        OauthUser oauthUser = createOauthUser(user);
        return oauthUserRepository.save(oauthUser);
    }

    private OauthUser createOauthUser(newUser user) {
        OauthUser oauthUser = new OauthUser();
        oauthUser.setEmail(user.email());
        oauthUser.setPassword(passwordEncoder.encode(user.password()));
        return oauthUser;
    }

    private void validateUser(newUser user) {
        oauthUserRepository.findByEmail(user.email())
                .ifPresent(u -> {
                    throw new InvalidUserException("user_already_exists");
                });
    }

    private void validatePassword(newUser user) {
        if (!user.password().equals(user.repeatPassword())) {
            throw new InvalidUserException("passwords_no_equal");
        }
    }
}
