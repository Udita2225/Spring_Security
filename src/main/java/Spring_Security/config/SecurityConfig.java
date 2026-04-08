package Spring_Security.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpRequest;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Bean
    @Order(SecurityFilterProperties.BASIC_AUTH_ORDER)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http){
        http.authorizeHttpRequests((requests)->
                requests.requestMatchers("/h2-console/**")
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                );
        http
                .sessionManagement((session)->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );
        http.headers(headers ->
                headers.frameOptions(
                        HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        /*
        http.headers(headers ->
                headers.frameOptions(
                        frameOptions -> frameOptions.sameOrigin()));
        */

        /*
        http.csrf(csrf -> csrf.disable());
        */
        http.csrf(AbstractHttpConfigurer::disable);
//        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        return http.build();
    }


    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 =  User.withUsername("user1")
//                .password("{noop}password1") //noop tells that password should be saved as plain text & should not be encoded. Not a good production practise
                .password(passwordEncoder().encode("password1"))
                .roles("USER")
                .build();
        UserDetails admin =  User.withUsername("admin")
                .password(passwordEncoder().encode("demo"))
                .roles("ADMIN")
                .build();

        JdbcUserDetailsManager userDetailsManager =  new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);
        return userDetailsManager;
//        return new InMemoryUserDetailsManager(user1, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
