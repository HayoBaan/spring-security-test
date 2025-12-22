package com.hayobaan.securitytest.controller;

import static com.hayobaan.securitytest.security.SecurityConfiguration.AUTHORITY_ADMIN;
import static com.hayobaan.securitytest.security.SecurityConfiguration.AUTHORITY_USER;

import com.hayobaan.securitytest.security.JwtUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Controlle. */
@RestController
@RequestMapping
public class Controller {
  @GetMapping("/getUserToken")
  public String getUserToken() {
    return JwtUtils.createToken("user", AUTHORITY_USER);
  }

  @GetMapping("/getAdminToken")
  public String getAdminToken() {
    return JwtUtils.createToken("admin", AUTHORITY_ADMIN);
  }

  @GetMapping("/getUserInfo")
  public String getUserInfo() {
    return "User Information["
        + SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString()
        + ']';
  }

  @GetMapping("/getAdminInfo")
  public String getAdminInfo() {
    return "Admin Information["
        + SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString()
        + ']';
  }
}
