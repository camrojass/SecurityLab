/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.example.menu.security;

/**
 * // com/example/menu/security/AudienceValidator.java
 * @author camrojass
 * mail camilo.rojas-s@mail.escuelaing.edu.co
 */
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;


import java.util.List;

/**
* La interfaz OAuth2TokenValidator y su método de validación proporcionan medios para verificar los atributos personalizados del token OAuth 2.0.
* Con la clase anterior, te aseguras de que solo sean válidos los tokens que contengan la audiencia especificada, o que aud afirme ser exactos.
*/
  
class AudienceValidator implements OAuth2TokenValidator<Jwt> {
  private final String audience;

  AudienceValidator(String audience) {
    Assert.hasText(audience, "audience is null or empty");
    this.audience = audience;
  }

  public OAuth2TokenValidatorResult validate(Jwt jwt) {
    List<String> audiences = jwt.getAudience();
    if (audiences.contains(this.audience)) {
      return OAuth2TokenValidatorResult.success();
    }
    OAuth2Error err = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN);
    return OAuth2TokenValidatorResult.failure(err);
  }
}
