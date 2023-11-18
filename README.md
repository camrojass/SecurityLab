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
cd menu-api-spring-boot-java
```
Instalar dependencias del proyecto usando Gradle:
```bash
./gradlew --refresh-dependencies
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
para los valores ```auth0.audience``` y ```auth0.audience```, siga los siguientes pasos en el portal de Auth0

Copie el valor identifier y péguelo en ```auth0.audience```
![image](https://github.com/camrojass/SecurityLab/assets/100396227/035bb511-4188-48c6-8f23-2761856326bd)
Copie el valor señalado y péguelo como valor en```auth0.audience```
![image](https://github.com/camrojass/SecurityLab/assets/100396227/93dfa649-d105-4c9b-ab36-858c4baeedaa)
Guarde los cambios, detenga e inicie el proyecto nuevamente con ```./gradlew bootRune```

### Spring Boot y Autorización

Para agregar el glujo de Gestión de identidad y acceso (IAM), debe agregar nuevas dependencias en el archivo ```build.gradle```
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

Una vez creada la aplicación de tipo *Aplicaciones web de una sola página*  en el panel de Auth0 (Ver paso a paso), 

<details><summary>Paso a paso</summary>
<p>
  
  #### Crear aplicación
  ![image](https://github.com/camrojass/SecurityLab/assets/100396227/af380aad-308b-4f04-a115-de7c788bc900)

  #### Ir a configuración
  ![image](https://github.com/camrojass/SecurityLab/assets/100396227/8bb310eb-173c-4935-93a4-8c36d188f81a)
  ![image](https://github.com/camrojass/SecurityLab/assets/100396227/6fcefe7f-7f30-4415-9243-15cd4607cc9e)
  
  #### Configurar los campos
  ![image](https://github.com/camrojass/SecurityLab/assets/100396227/3991faf4-0426-467a-8035-1e70a2bfb5ac)


  
</details></p>

En la aplicación cliente ["WHATABYTE Dashboard"](https://dashboard.whatabyte.app/), ingrese a la pestaña *Configuración* para acceder a los valores de configuración de la aplicación cliente

![image](https://github.com/camrojass/SecurityLab/assets/100396227/91bbeb21-1429-47d4-a4d2-4aff749052e6)

En dado caso que no aparezcan las características de autendicación, habilítelas, y diligencie de la siguiente manera

*Auth0 Domain* :
![image](https://github.com/camrojass/SecurityLab/assets/100396227/bbb85f68-1768-47e9-9d93-bb4bc591e608)

*Auth0 Client ID* :
![image](https://github.com/camrojass/SecurityLab/assets/100396227/bae1ce3f-0e6a-4c28-8750-c35c1920f69f)

*Auth0 Auth0 CallBack URL* :
![image](https://github.com/camrojass/SecurityLab/assets/100396227/6fa1b87a-1d5f-49a9-9193-1237972fd7a6)

*Auth0 API Audience* :
![image](https://github.com/camrojass/SecurityLab/assets/100396227/edf39f01-de76-465a-aca0-9209cdf7de49)
NOTA: Los valores de ```Auth0 Auth0 CallBack URL``` y ```Auth0 API Audience``` deben estar parametrizados en la aplicacion creada en Auth0
![image](https://github.com/camrojass/SecurityLab/assets/100396227/a0101113-43b5-4832-ae7a-8d71a1e503ce)


### Habilitar CORS en Sprint Boot

Actualice la clase ```SecurityConfig``` con la siguiente información

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

También elimine la siguiente línea de ```ItemsController```:
```
@CrossOrigin(origins = "https://dashboard.whatabyte.app")
```
Detenga el proyecto y ejecútelo nuevamente para que los cambios sean efectivos
```bash
./gradlew bootRun
```
### Inicio de sesión
En la aplicación cliente, haga clic en iniciar sesión (Sign In). Esto debe direccionarlo a la página de inicio creada en Auth0 para iniciar sesión o registrarse.
![image](https://github.com/camrojass/SecurityLab/assets/100396227/25dd6bec-685e-43c8-847a-3f67a0b22477)
Registrese y la aplicación actualizará su información con la información del registro realizado
![image](https://github.com/camrojass/SecurityLab/assets/100396227/0049b608-45d2-42f7-8db0-b8c1056881d7)
![image](https://github.com/camrojass/SecurityLab/assets/100396227/f1dbe179-04f5-426d-b07b-8757b9232dfb)
O ingrese a la información del usuario, si se loggeo a través de otra sesión como gmail, mostrará la imagen de gmail en su usuario
![image](https://github.com/camrojass/SecurityLab/assets/100396227/9717455a-e62a-4166-adec-a89931cafc4b)

## Evidencia

### Validación Protección de terminales
Una vez hecho realizado el registro de la aplicación y habilitado los CORS en Spring Boot, podrá validar que los cambios solo los pueda realizar los usuarios registrados
<details><summary>Usuario Registrado</summary>
<p>

  Agregar nuevo plato al menú
  ![image](https://github.com/camrojass/SecurityLab/assets/100396227/3bce7dcb-d9ac-4a53-9c0e-51625390382c)
  ![image](https://github.com/camrojass/SecurityLab/assets/100396227/521086b4-3352-435d-a9a3-5112fda24032)

  
</details></p>

<details><summary>Usuario NO Registrado</summary>
<p>
  
  Agregar nuevo plato al menú
  ![image](https://github.com/camrojass/SecurityLab/assets/100396227/11fdc3f1-f5b6-4aae-8989-3b6d0e27dbcb)
  Eliminar un plato del menú
  ![image](https://github.com/camrojass/SecurityLab/assets/100396227/cb4cef76-c033-4e73-9e8b-d3a6aebbb024)
  Editar un plato del menú
  ![image](https://github.com/camrojass/SecurityLab/assets/100396227/e4d5ef2f-8194-4b41-84bb-bec9e53461e1)

**NOTA** Para realizar la prueba, se deshabilita las caracteristicas de autenticación lo que impide que un usuario pueda conectarse.
</details></p>

## Autores
* **Auth0** - *Repositorio original* - [Auth0 Blog Samples](https://github.com/auth0-blog)
* **Camilo Alejandro Rojas** - *Trabajo y documentación* - [camrojass](https://github.com/camrojass)

## Bibliografía
* Tutorial de autorización de Spring Boot: Protegener una API (Java). Url: https://auth0.com/blog/spring-boot-authorization-tutorial-secure-an-api-java/
* Repositorio GitHub. Url: https://github.com/auth0-blog/menu-api-spring-boot-java.git
