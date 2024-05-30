package be.yorian.service;

import be.yorian.entity.OauthUser;
import be.yorian.entity.newUser;


public interface UserService {

    OauthUser createUser(newUser user);
}
