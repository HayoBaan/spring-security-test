package com.hayobaan.securitytest;

import static com.hayobaan.securitytest.security.SecurityConfiguration.AUTHORITY_ADMIN;
import static com.hayobaan.securitytest.security.SecurityConfiguration.AUTHORITY_USER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hayobaan.securitytest.controller.Controller;
import com.hayobaan.securitytest.security.JwtUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

@WebMvcTest(controllers = {Controller.class})
@ComponentScan("com.hayobaan")
class SecurityConfigurationTest {
  @Autowired private MockMvc mockMvc;

  @ParameterizedTest
  @ValueSource(strings = {AUTHORITY_ADMIN, AUTHORITY_USER})
  void testEndpointSecurityAlwaysOk(String authority) throws Exception {
    var builder = MockMvcRequestBuilders.get("/get" + authority + "Token");
    var result = mockMvc.perform(builder).andReturn();

    assertNotNull(result);
    var response = result.getResponse();
    assertEquals(200, response.getStatus());
    assertTrue(response.getContentAsString().startsWith("Bearer "));
  }

  @ParameterizedTest
  @ValueSource(strings = {AUTHORITY_ADMIN, AUTHORITY_USER})
  void testEndpointSecurityAuthorized(String authority) throws Exception {
    var builder = MockMvcRequestBuilders.get("/get" + authority + "Info");
    builder.header(HttpHeaders.AUTHORIZATION, JwtUtils.createToken("authenticatedUser", authority));
    var result = mockMvc.perform(builder).andReturn();

    assertNotNull(result);
    var response = result.getResponse();
    assertEquals(200, response.getStatus());
    assertEquals(authority + " Information[authenticatedUser]", response.getContentAsString());
  }

  @Test
  void testEndpointSecurityAdminAuthorized() throws Exception {
    var builder = MockMvcRequestBuilders.get("/getUserInfo");
    builder.header(
        HttpHeaders.AUTHORIZATION, JwtUtils.createToken("authenticatedUser", AUTHORITY_ADMIN));
    var result = mockMvc.perform(builder).andReturn();

    assertNotNull(result);
    var response = result.getResponse();
    assertEquals(200, response.getStatus());
    assertEquals("User Information[authenticatedUser]", response.getContentAsString());
  }

  @Test
  void testEndpointSecurityUserNotAuthorized() throws Exception {
    var builder = MockMvcRequestBuilders.get("/getAdminInfo");
    builder.header(
        HttpHeaders.AUTHORIZATION, JwtUtils.createToken("authenticatedUser", AUTHORITY_USER));
    var result = mockMvc.perform(builder).andReturn();

    assertNotNull(result);
    var response = result.getResponse();
    assertEquals(403, response.getStatus());
  }

  @Test
  void testEndpointSecurityMethodNotAuthorized() throws Exception {
    var builder = MockMvcRequestBuilders.post("/getUserToken");
    var result = mockMvc.perform(builder).andReturn();

    assertNotNull(result);
    var response = result.getResponse();
    assertEquals(403, response.getStatus());
  }
}
