package example.hellosecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class DefaultSecurityConfig {
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .formLogin(form ->
                        form.loginPage("/login.html")
                                .permitAll()
                );

        return http.build();
    }
}
