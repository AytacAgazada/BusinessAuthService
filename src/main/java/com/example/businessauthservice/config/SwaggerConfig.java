package com.example.businessauthservice.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("BusinessAuthService API")
                        .version("1.0.0")
                        .description("Authentication and User Management Service API Documentation")
                        .termsOfService("http://swagger.io/terms/")
                        .contact(new Contact().name("Your Name").email("your.email@example.com"))
                        .license(new License().name("Apache 2.0").url("http://springdoc.org")))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth")) // JWT üçün tələb əlavə edir
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme() // JWT üçün security scheme təyin edir
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")));
    }
}
