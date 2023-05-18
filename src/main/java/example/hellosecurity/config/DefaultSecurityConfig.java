package example.hellosecurity.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;


/*
* Spring'in filter chain'ini bean olarak yayimlar.
* Her istek icin Spring Security'nin filter chain'ini uygulamanin filter'larina baglar
* */
@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {

    @Bean
    /*
    * ConditionalOnMissingBean anotasyonu ile UserDetailsService bean'i yok ise yaratilip inject edilecek
    * UserDetaisService user'in username'i ve generate edilen password'unu console'a loglar ve projeye publish eder
    */
    @ConditionalOnMissingBean(UserDetailsService.class)
    InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        String generatedPassword = "{noop}123123"; //{noop} anahtar kelimesi kullanilmaz ise exception aliyoruz. Cunku encrypted password degil
        /*
        * InMemoryUserDetailsManager cok az kullanici olan durumlarda kullanilir
        * username - password ve role ile kullanici olusturulur.
        * application yasam suresi boyunca bu user'lar ram'de tutulurlar
        * */
        return new InMemoryUserDetailsManager(
                User.withUsername("ocean")
                        .password(generatedPassword)
                        .roles("USER")
                        .build());
    }

    @Bean
    /*
    * AuthenticationEventPublisher authentication olaylarını yayınlar
    * DefaultAuthenticationEventPublisher ise bilinen AuthenticationException turlerini event'lerle eslestirir
    * ve bunlari application context araciligi ile yayinlar
    * Bean olarak yapilandirilirsa ApplicationEventPublisher'i otomataik olarak alir.
    * Aksi takdirde ApplicationEventPublisher'i method argumani olarak almalidir
    * */
    @ConditionalOnMissingBean(AuthenticationEventPublisher.class)
    DefaultAuthenticationEventPublisher defaultAuthenticationEventPublisher(ApplicationEventPublisher delegate) {
        return new DefaultAuthenticationEventPublisher(delegate);
    }

}
