package com.cy.security.crowd;

import com.atlassian.crowd.exception.*;
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticator;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.pam.UnsupportedTokenException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * Created by mars on 2015/3/6.
 */
@Slf4j
public class CrowdRealm extends AuthorizingRealm {

    private CrowdHttpAuthenticator crowdHttpClient;

    public CrowdRealm() {
        super();
        setAuthenticationTokenClass(CrowdUserToken.class);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        if(authenticationToken ==null){
            throw new CrowdAuthenticationException("token is null");
        }
        if (!(authenticationToken instanceof CrowdUserToken)) {
            throw new UnsupportedTokenException("Unsupported token of type " + authenticationToken.getClass().getName() + ".  "
                    + UsernamePasswordToken.class.getName() + " is required.");
        } else {
            CrowdUserToken token = (CrowdUserToken) authenticationToken;
            try {
                crowdHttpClient.authenticate(token.getRequest(), token.getResponse(), token.getUserId(), String.valueOf(token.getPassword()));
                return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
            } catch (ApplicationAccessDeniedException aade) {
                throw new AuthenticationException("Unable to obtain authenticate principal " + token.getUserId() + " in Crowd.", aade);
            } catch (InvalidAuthenticationException iae) {
                throw new IncorrectCredentialsException("Unable to authenticate principal " + token.getUserId() + " in Crowd.", iae);
            } catch (InactiveAccountException iae) {
                throw new DisabledAccountException("Disabled principal " + token.getUserId() + " in Crowd.", iae);
            } catch (InvalidTokenException e) {
                throw new CrowdAuthenticationException("InvalidTokenException ", e);
            } catch (ExpiredCredentialException e) {
                throw new CrowdAuthenticationException(" ExpiredCredentialException ", e);
            } catch (OperationFailedException e) {
                throw new CrowdAuthenticationException(" OperationFailedException ", e);
            } catch (ApplicationPermissionException e) {
                throw new CrowdAuthenticationException(" ApplicationPermissionException ", e);
            }
        }

    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        final String userId = (String) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        addRole(userId, info);
        return info;
    }

    private void addRole(String userId, SimpleAuthorizationInfo info) {
        switch (userId) {
            case "admin":
                addRoleAndPermission("admin", info);
                break;
            case "pixie":
                addRoleAndPermission("employee", info);
                addRoleAndPermission("hr", info);
                break;
            case "lulu":
                addRoleAndPermission("employee", info);
                addRoleAndPermission("fin", info);
                addRoleAndPermission("manager", info);
                addRoleAndPermission("manager_fin", info);
                break;
            case "connie":
                addRoleAndPermission("employee", info);
                addRoleAndPermission("fin", info);
                break;
        }
    }

    private void addRoleAndPermission(String roleName, SimpleAuthorizationInfo info) {
        switch (roleName) {
            case "admin":
                info.addRole("admin");
                info.addStringPermission("*");
                break;
            case "employee":
                info.addRole("employee");
                info.addStringPermission("employee:*");
                break;
            case "hr":
                info.addRole("hr");
                info.addStringPermission("hr:*");
                break;
            case "fin":
                info.addRole("fin");
                info.addStringPermission("fin:gl:create");
                info.addStringPermission("fin:gl:update");
                break;
            case "manager_fin":
                info.addRole("manager_fin");
                info.addStringPermission("fin:manager:*");
                info.addStringPermission("fin:gl:*");
                break;
            case "manager":
                info.addRole("manager");
                info.addStringPermission("manager:*");
                break;
        }

    }

    @Override
    public void setAuthenticationTokenClass(Class<? extends AuthenticationToken> authenticationTokenClass) {
        super.setAuthenticationTokenClass(CrowdUserToken.class);
    }

    public String getPassword() {
        return "1234";
    }
}
