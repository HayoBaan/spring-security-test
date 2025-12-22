package com.hayobaan.securitytest.security;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * This filter is responsible setting the {@link Authentication} in the security context based on
 * the JWT in the request.
 */
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    log.debug("Inside JwtAuthenticationFilter.doFilter");
    super.doFilter(request, response, filterChain);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    log.debug("Inside JwtAuthenticationFilter.doFilterInternal");
    try {
      var token = request.getHeader(HttpHeaders.AUTHORIZATION);
      var authentication = JwtUtils.parseToken(token);
      if (authentication != null) {
        log.debug("Authenticated: {}", authentication);
      } else {
        log.debug("Not authenticated");
      }
      SecurityContextHolder.getContext().setAuthentication(authentication);
    } catch (Exception e) {
      // Handle authentication errors by setting the response status to Unauthorized (401)
      // and the WWW-Authenticate header to “Bearer”.
      var message = e.getMessage();
      if (e instanceof ExpiredJwtException ee) {
        message += " User: " + ee.getClaims().getSubject() + '.';
      }
      log.warn("{} {}", request, message, e);
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
      SecurityContextHolder.clearContext();
      return;
    }
    filterChain.doFilter(request, response);
  }
}
