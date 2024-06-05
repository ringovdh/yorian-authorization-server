package be.yorian.service;

import be.yorian.entity.OauthUser;
import be.yorian.entity.NewUser;
import be.yorian.exception.InvalidUserException;
import be.yorian.repository.OauthUserRepository;
import be.yorian.repository.RoleRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class UserServiceImpl implements UserService {

    private final OauthUserRepository oauthUserRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(OauthUserRepository oauthUserRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder) {
        this.oauthUserRepository = oauthUserRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public OauthUser createUser(NewUser user) {
        validatePassword(user);
        validateUser(user);
        OauthUser oauthUser = createOauthUser(user);
        return oauthUserRepository.save(oauthUser);
    }

    private OauthUser createOauthUser(NewUser user) {
        OauthUser oauthUser = new OauthUser();
        oauthUser.setEmail(user.email());
        oauthUser.setPassword(passwordEncoder.encode(user.password()));
        oauthUser.getRoles().add(roleRepository.findByName("USER"));
        return oauthUser;
    }

    private void validateUser(NewUser user) {
        oauthUserRepository.findByEmail(user.email())
                .ifPresent(u -> {
                    throw new InvalidUserException("user_already_exists");
                });
    }

    private void validatePassword(NewUser user) {
        if (!user.password().equals(user.repeatPassword())) {
            throw new InvalidUserException("passwords_no_equal");
        }
    }
}
