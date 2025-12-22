package com.hayobaan.securitytest.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/** This utility class provides functionality to create and parse JSON Web Tokens (JWT). */
public class JwtUtils {
  /** The Bearer token prefix. */
  private static final String BEARER_TOKEN_PREFIX = "Bearer ";

  /** The field name for the claim authorities. */
  private static final String CLAIM_AUTHORITIES = "aut";

  /** The token secret. */
  private static final byte[] SECRET =
      "secret-secret-secret-secret-secret-secret-secret-secret-secret-secret-secret-secret-secret-secret-secret-secret-secret-secret-secret-secret-secret"
          .getBytes(StandardCharsets.UTF_8);

  /** The token expiration time. */
  private static final long EXPIRATION_TIME = 864_000_000;

  /** Private constructor to prevent instantiation. */
  private JwtUtils() {
    // Prevent instantiation
  }

  /**
   * Creates a JWT token for the given user and authorities.
   *
   * @param name the name of the user.
   * @param authorities the comma separated list of authorities.
   * @return the created JWT token.
   */
  public static String createToken(String name, String authorities) {
    var key = Keys.hmacShaKeyFor(SECRET);
    return BEARER_TOKEN_PREFIX
        + Jwts.builder()
            .subject(name)
            .claim(CLAIM_AUTHORITIES, authorities)
            .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
            .signWith(key, Jwts.SIG.HS512)
            .compact();
  }

  /**
   * Parses the given authorization header JWT (including the Bearer prefix) into an authentication
   * object. An exception is thrown if the token was invalid.
   *
   * <p>Note: the details in the token are unpacked as JSON node into the authentication object.
   *
   * @param token the JWT token.
   * @return the authentication for the user or null if the token was not a Bearer token.
   */
  public static Authentication parseToken(String token) {
    if (token != null && token.startsWith(BEARER_TOKEN_PREFIX)) {
      token = token.substring(BEARER_TOKEN_PREFIX.length());
      var key = Keys.hmacShaKeyFor(SECRET);
      var parser = Jwts.parser().verifyWith(key).build();
      var claims = parser.parseSignedClaims(token).getPayload();
      var user = claims.getSubject();
      if (isNullOrEmpty(user)) {
        throw new IllegalArgumentException("No user specified in token");
      }
      var authoritiesString = claims.get(CLAIM_AUTHORITIES, String.class);
      var grantedAuthorities = convertToGrantedAuthorities(authoritiesString);

      return new UsernamePasswordAuthenticationToken(user, "password", grantedAuthorities);
    }

    return null;
  }

  private static boolean isNullOrEmpty(String detailsString) {
    return detailsString == null || detailsString.isEmpty();
  }

  /**
   * Converts a comma separated string of authorities to a collection of granted authorities.
   *
   * @param authorities the comma separated string of authorities.
   * @return the granted authorities from the authorities.
   */
  private static Collection<GrantedAuthority> convertToGrantedAuthorities(String authorities) {
    Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
    if (authorities != null) {
      for (var authority : authorities.split(",")) {
        authority = authority.strip();
        if (!authority.isEmpty()) {
          grantedAuthorities.add(new SimpleGrantedAuthority(authority));
        }
      }
    }
    return grantedAuthorities;
  }
}
