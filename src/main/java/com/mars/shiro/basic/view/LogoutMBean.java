package com.mars.shiro.basic.view;

import com.mars.shiro.basic.service.LogoutService;
import lombok.extern.slf4j.Slf4j;
import org.omnifaces.util.Faces;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.RequestScoped;
import java.io.IOException;

/**
 * Created by mars on 2015/2/16.
 */
@Slf4j
@ManagedBean
@RequestScoped
public class LogoutMBean {

    @EJB
    private LogoutService logoutService;
    private static final String PORTAL_CONTEXT = "/shiro-basic";

    public void logout() {
        logoutService.logout();
        try {
            Faces.redirect(PORTAL_CONTEXT + "/index.xhtml");
        } catch (IOException e) {
            log.error("redirect fail ", e);
        }
    }

}
