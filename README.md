# SecurityLab

**URL GitHub:** https://github.com/camrojass/SecurityLab.git

## Resumen
El repositorio contiene la implementación de seguridad, con Auth0 a una API Spring Boot construida en Java y la App cliente ["WHATABYTE Dashboard"](https://dashboard.whatabyte.app/), aplicando el principio de mediación completa (Autorización, autenticación e integralidad).

## Preciondiciones

### Clonar repositorio
Clona el repositorio de la aplicación y consulta la rama: ```main ```
```bash
git clone git@github.com:auth0-blog/menu-api-spring-boot-java.git \
```
Abrir carpeta del proyecto en directorio actual
```bash
cd menu-api
```
Instalar dependencias dle proyecto usando Gradle:
```bash
cd menu-api
```
Verificar el archivo ```application.properties ``` en la ruta ```src/main/resources ```
```java
server.port=7000
```
Finalmente, ejecute el proyecto con el siguiente comando
```bash
./gradlew bootRun
```
![image](https://github.com/camrojass/SecurityLab/assets/100396227/2e1f60e3-2c03-4310-b562-8233b50aa638)

### Crear cuenta en [Auth0](https://auth0.com/signup)
### Tener un IDE disponible 

## Implementación

Abra el archivo ```application.properties``` en la ruta ```src/main/resources``` y actualícelo:
```java
server.port=7000
auth0.audience=
auth0.domain=
spring.security.oauth2.resourceserver.jwt.issuer-uri=https://${auth0.domain}/
```

Para proteger su API, debe agregar algunas nuevas dependencias en el archivo ```build.gradle```

### Spring Boot y Autorización
```java
dependency {
  implementation 'org.springframework.boot:spring-boot-starter-security'
  implementation 'org.springframework.security:spring-security-oauth2-resource-server'
  implementation 'org.springframework.security:spring-security-oauth2-jose'
  // ...
}
```
Se debe sincronizar gradle y crear un nuevo paquete ```security``` debajo del paquete ```com.example.menu```
Posterior a eso se agrega las clases ```SecurityConfig``` y ```AudienceValidator```

<details><summary>SecurityConfig</summary>
<p>

```java
// com/example/menu/security/SecurityConfig.java

package com.example.menu.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
  @Value("${auth0.audience}")
  private String audience;

  @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
  private String issuer;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
      .mvcMatchers(HttpMethod.GET, "/api/menu/items/**").permitAll() // GET requests don't need auth
      .anyRequest()
      .authenticated()
      .and()
      .oauth2ResourceServer()
      .jwt()
      .decoder(jwtDecoder());
  }

  JwtDecoder jwtDecoder() {
    OAuth2TokenValidator<Jwt> withAudience = new AudienceValidator(audience);
    OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
    OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withAudience, withIssuer);

    NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromOidcIssuerLocation(issuer);
    jwtDecoder.setJwtValidator(validator);
    return jwtDecoder;
  }
}
```
</details></p>

<details><summary>AudienceValidator</summary>
<p>

```java
// com/example/menu/security/AudienceValidator.java

package com.example.menu.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.Objects;

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
```
</details></p>

### Registrar aplicación de cliente en Auth0

Una vez creada la aplicación de tipo *Aplicaciones web de una sola página*  en el panel de Auth0, ingrese a la pestaña *Configuración* para acceder a los valores de configuración de la aplicación cliente
![image](https://github.com/camrojass/SecurityLab/assets/100396227/91bbeb21-1429-47d4-a4d2-4aff749052e6)
En dado caso que no aparezcan las características de autendicación, habilítelas, y diligencie de la siguiente manera

*Auth0 Domain* :

*Auth0 client ID* :

*Auth0 Auth0 CallBack URL* :

*Auth0 API Audience* :

### Habilitar CORS en Sprint Boot

<details><summary>SecurityConfig</summary>
<p>

```java
// com/example/menu/security/SecurityConfig.java

package com.example.menu.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Value("${auth0.audience}")
    private String audience;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers(HttpMethod.GET, "/api/menu/items/**").permitAll() // GET requests don't need auth
                .anyRequest()
                .authenticated()
                .and()
                .cors()
                .configurationSource(corsConfigurationSource())
                .and()
                .oauth2ResourceServer()
                .jwt()
                .decoder(jwtDecoder());
    }

    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedMethods(List.of(
                HttpMethod.GET.name(),
                HttpMethod.PUT.name(),
                HttpMethod.POST.name(),
                HttpMethod.DELETE.name()
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration.applyPermitDefaultValues());
        return source;
    }

    JwtDecoder jwtDecoder() {
        OAuth2TokenValidator<Jwt> withAudience = new AudienceValidator(audience);
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withAudience, withIssuer);

        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromOidcIssuerLocation(issuer);
        jwtDecoder.setJwtValidator(validator);
        return jwtDecoder;
    }
}
```
</details></p>
Detenga el proyecto y ejecútelo nuevamente para que los cambios sean efectivos
```bash
./gradlew bootRun
```


## Autores
* **Auth0** - *Repositorio original* - [Auth0 Blog Samples](https://github.com/auth0-blog)
* **Camilo Alejandro Rojas** - *Trabajo y documentación* - [camrojass](https://github.com/camrojass)

## Bibliografía
* Tutorial de autorización de Spring Boot: Protegener una API (Java). Url: https://auth0.com/blog/spring-boot-authorization-tutorial-secure-an-api-java/
* Repositorio GitHub. Url: https://github.com/auth0-blog/menu-api-spring-boot-java.git
