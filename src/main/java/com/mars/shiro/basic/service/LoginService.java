package com.mars.shiro.basic.service;

import com.atlassian.crowd.integration.http.filter.CrowdSecurityFilter;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.omnifaces.util.Faces;

import javax.ejb.Stateless;

/**
 * Created by mars on 2015/2/16.
 */
@Slf4j
@Stateless
public class LoginService extends BaseAction {

    public void authenticate(UsernamePasswordToken token) throws AuthenticationException {

        String username = token.getUsername();
        char[] password = token.getPassword();

        if (username != null && !username.equals("") && password != null) {
            crowdHttpAuthenticator.authenticate(Faces.getRequest(),
                    Faces.getResponse(), username, password);
            String requestingPage = (String) getSession().getAttribute(
                    CrowdSecurityFilter.ORIGINAL_URL);
            if (requestingPage != null) {
                Faces.getResponse().sendRedirect(requestingPage);
                return;
            } else {
                Faces.redirect("secure/welcomePrimefaces.xhtml");
            }
        } else {
            // didn't supply authentication information, check if already
            // authenticated
            if (isAuthenticated()) {
                Faces.redirect("secure/welcomePrimefaces.xhtml");
            }
        }



        Subject currentUser = SecurityUtils.getSubject();
        try {
            currentUser.login(token);
        } catch (IncorrectCredentialsException | UnknownAccountException ie) {
            throw new AuthenticationException();
        } catch (AuthenticationException e) {
            log.warn(e.getMessage(), e);
            throw e;
        }
    }
}
