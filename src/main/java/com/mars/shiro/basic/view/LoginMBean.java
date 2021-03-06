/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mars.shiro.basic.view;

import com.mars.shiro.basic.service.LoginService;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.omnifaces.util.Messages;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.RequestScoped;

/**
 * @author mars
 */
@Slf4j
@ManagedBean
@RequestScoped
public class LoginMBean {

    @EJB
    private LoginService loginService;

    @Getter
    @Setter
    private String userId;

    @Getter
    @Setter
    private String password;

    @Getter
    @Setter
    private boolean rememberMe = false;

    /**
     * Creates a new instance of LoginMBean
     */
    public LoginMBean() {
    }

    public String authenticate() {
        UsernamePasswordToken token = new UsernamePasswordToken(userId, password, rememberMe);
        try {
            loginService.authenticate(token);
            Subject currentUser = SecurityUtils.getSubject();
            log.info("User :" + currentUser.getPrincipal() + "has login");
            log.info("currentUser.isPermitted(\"create\")" + currentUser.isPermitted("create"));
            return "/system/secret";
        } catch (EJBException ejbException) {
            Exception e = ejbException.getCausedByException();
            if (e.getClass().getName().equals("AuthenticationException")) {
                Messages.addFlashGlobalError("登入失敗 ,您輸入的帳號或密碼有誤。");
            }
        } catch (AuthenticationException e) {
            log.warn(e.getMessage());
            Messages.addFlashGlobalError("登入失敗 ,您輸入的帳號或密碼有誤。");
        }
        return "";
    }

}
