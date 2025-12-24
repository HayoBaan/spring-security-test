package com.hayobaan.securitytest.security;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/** This class is responsible for creating the Spring beans that are used for security. */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
  /** The authority “user.” */
  public static final String AUTHORITY_USER = "User";

  /** The authority “admin.” */
  public static final String AUTHORITY_ADMIN = "Admin";

  /**
   * Creates the JWT authentication filter bean. The bean is only created if not already present.
   *
   * @return the JWT authentication filter bean.
   */
  @Bean
  public JwtAuthenticationFilter jwtAuthenticationFilter() {
    return new JwtAuthenticationFilter();
  }

  /**
   * Creates the URL based CORS configuration source bean. The bean is only created if not already
   * present.
   *
   * @return the URL based CORS configuration source bean.
   */
  @Bean
  public UrlBasedCorsConfigurationSource configurationSource() {
    var corsConfig = new CorsConfiguration();
    corsConfig.setAllowCredentials(true);
    corsConfig.setAllowedOrigins(null);
    corsConfig.setAllowedOriginPatterns(List.of(CorsConfiguration.ALL));
    corsConfig.addAllowedHeader(HttpHeaders.AUTHORIZATION);
    corsConfig.addAllowedHeader(HttpHeaders.CONTENT_TYPE);
    corsConfig.addAllowedMethod(CorsConfiguration.ALL);
    corsConfig.addExposedHeader(HttpHeaders.AUTHORIZATION);
    corsConfig.addExposedHeader(HttpHeaders.CONTENT_DISPOSITION);
    corsConfig.addExposedHeader(HttpHeaders.CONTENT_LENGTH);
    corsConfig.addExposedHeader(HttpHeaders.CONTENT_TYPE);
    var source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", corsConfig);
    return source;
  }

  /**
   * Builds the security filter chain from the specified {@link HttpSecurity}.
   *
   * @param httpSecurity the http security
   * @param jwtAuthenticationFilter the jwt authentication filter
   * @param corsConfigurationSource the cors configuration source
   * @return the security filter chain
   */
  @Bean
  @SuppressWarnings("java:S4502") // Safe to disable CSRF
  public SecurityFilterChain filterChain(
      HttpSecurity httpSecurity,
      JwtAuthenticationFilter jwtAuthenticationFilter,
      UrlBasedCorsConfigurationSource corsConfigurationSource) {
    httpSecurity
        .headers(h -> h.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
        .cors(c -> c.configurationSource(corsConfigurationSource))
        .csrf(AbstractHttpConfigurer::disable)
        .httpBasic(AbstractHttpConfigurer::disable)
        .sessionManagement(
            sessionManagement ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    httpSecurity
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers(HttpMethod.GET, "/getUserToken", "/getAdminToken")
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/getUserInfo")
                    .hasAnyAuthority(AUTHORITY_USER, AUTHORITY_ADMIN)
                    .requestMatchers(HttpMethod.GET, "/getAdminInfo")
                    .hasAuthority(AUTHORITY_ADMIN))
        .authorizeHttpRequests(a -> a.anyRequest().denyAll());

    httpSecurity.addFilterBefore(
        jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    return httpSecurity.build();
  }
}
