package be.yorian.service;

import be.yorian.entity.OauthUser;
import be.yorian.entity.NewUser;


public interface UserService {

    OauthUser createUser(NewUser user);
}
