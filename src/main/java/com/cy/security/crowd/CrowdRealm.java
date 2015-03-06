package com.cy.security.crowd;

import com.atlassian.crowd.integration.http.CrowdHttpAuthenticator;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * Created by mars on 2015/3/6.
 */
@Slf4j
public class CrowdRealm extends AuthorizingRealm {

    private SecurityServerClient crowdClient;
    private CrowdHttpAuthenticator crowdHttpAuthenticator;


    public CrowdRealm() {
        super();
        setAuthenticationTokenClass(CrowdUserToken.class);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        if (token instanceof CrowdUserToken) {
            CrowdUserToken authcToken = (CrowdUserToken) token;
        }
        String userId = token.getPrincipal().toString();

        if (userId == null) {
            log.warn("UserId is null.");
            return null;
        }
        String passwordSalt = getPassword();
        return new SimpleAuthenticationInfo(userId, passwordSalt, getName());
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
