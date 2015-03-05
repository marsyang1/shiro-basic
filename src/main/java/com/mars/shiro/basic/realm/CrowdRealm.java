package com.mars.shiro.basic.realm;

import com.atlassian.crowd.exception.ApplicationAccessDeniedException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.InvalidAuthorizationTokenException;
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticator;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.pam.UnsupportedTokenException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.rmi.RemoteException;

/**
 * Created by mars on 2015/3/4.
 */
@Slf4j
public class CrowdRealm extends AuthorizingRealm {

    private SecurityServerClient crowdClient;
    private CrowdHttpAuthenticator crowdHttpAuthenticator;

    public CrowdClient(){

    }

    public CrowdRealm(SecurityServerClient crowdClient) {
        if (crowdClient == null) throw new IllegalArgumentException("Crowd client cannot be null");
        this.crowdClient = crowdClient;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken authcToken = (UsernamePasswordToken) authenticationToken;
        String userId = authcToken.getUsername();

        if (!(authenticationToken instanceof UsernamePasswordToken)) {
            throw new UnsupportedTokenException("Unsupported token of type " + authenticationToken.getClass().getName() + ".  "
                    + UsernamePasswordToken.class.getName() + " is required.");
        } else {

            UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
            try {
                crowdClient.authenticatePrincipalSimple(token.getUsername(), new String(token.getPassword()));
                return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
            } catch (InvalidAuthorizationTokenException iate) {
                throw new AuthenticationException("Unable to obtain authenticate principal " + token.getUsername() + " in Crowd.", iate);
            } catch (ApplicationAccessDeniedException aade) {
                throw new AuthenticationException("Unable to obtain authenticate principal " + token.getUsername() + " in Crowd.", aade);
            } catch (InvalidAuthenticationException iae) {
                throw new IncorrectCredentialsException("Unable to authenticate principal " + token.getUsername() + " in Crowd.", iae);
            } catch (RemoteException re) {
                throw new AuthenticationException("Unable to obtain authenticate principal " + token.getUsername() + " in Crowd.", re);
            } catch (InactiveAccountException iae) {
                throw new DisabledAccountException("Disabled principal " + token.getUsername() + " in Crowd.", iae);
            }
        }

    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return;
    }

}
