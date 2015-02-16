package com.mars.shiro.basic.service;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;

import javax.ejb.Stateless;

/**
 * Created by mars on 2015/2/16.
 */
@Slf4j
@Stateless
public class LoginService {

    public void authenticate(UsernamePasswordToken token) throws AuthenticationException {
        Subject currentUser = SecurityUtils.getSubject();
        try {
            currentUser.login(token);
        } catch (AuthenticationException e) {
            log.warn(e.getMessage(), e);
            throw e;
        }
    }
}
