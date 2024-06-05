package be.yorian.manager;

import be.yorian.entity.OauthUser;
import be.yorian.repository.OauthUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

@Service
public class JpaUserDetailsManager implements UserDetailsManager {

    private final OauthUserRepository oauthUserRepository;

    @Autowired
    public JpaUserDetailsManager(OauthUserRepository oauthUserRepository) {
        this.oauthUserRepository = oauthUserRepository;
    }


    @Override
    public void createUser(UserDetails user) {

    }

    @Override
    public void updateUser(UserDetails user) {

    }

    @Override
    public void deleteUser(String username) {

    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {

    }

    @Override
    public boolean userExists(String username) {
        return false;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        OauthUser oauthUser = oauthUserRepository.findByEmail(email).orElseThrow(()-> new UsernameNotFoundException("user_not_found"));
        return new User(oauthUser.getEmail(), oauthUser.getPassword(), oauthUser.getAuthorities());
    }
}
