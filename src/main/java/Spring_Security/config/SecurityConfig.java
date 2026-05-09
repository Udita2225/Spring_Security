package Spring_Security.config;


import Spring_Security.jwt.AuthEntryPointJwt;
import Spring_Security.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter(){
        return new AuthTokenFilter();
    }

    @Bean
    @Order(SecurityFilterProperties.BASIC_AUTH_ORDER)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http){
        http.authorizeHttpRequests((authorizeRequests)->
                authorizeRequests.requestMatchers("/h2-console/**")
                        .permitAll()
                        .requestMatchers("/signin")
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                );

        http.sessionManagement((session)->
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

//       We are telling spring security that hey if any exception occurs then we have a custom exception handler .. use it
          http.exceptionHandling(exception->
                  exception.authenticationEntryPoint(unauthorizedHandler)
                  );

          http.addFilterBefore(authenticationJwtTokenFilter(),
                  UsernamePasswordAuthenticationFilter.class);

//        http.formLogin(withDefaults());
//        http.httpBasic(withDefaults());
        return http.build();
    }

//   We have to use CommandLineRunner so that database will be created the moment the application gets loaded
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource){
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService){
        return args ->{
          JdbcUserDetailsManager manager = (JdbcUserDetailsManager)  userDetailsService;
          UserDetails user1 = User.withUsername("user1")
                  .password(passwordEncoder().encode("password1"))
                  .roles("USER")
                  .build();
          UserDetails admin = User.withUsername("admin")
                  .password(passwordEncoder().encode("adminPass"))
                  .roles("ADMIN")
                  .build();

          JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
          userDetailsManager.createUser(user1);
          userDetailsManager.createUser(admin);
        };
    }






//
//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails user1 =  User.withUsername("user1")
////                .password("{noop}password1") //noop tells that password should be saved as plain text & should not be encoded. Not a good production practise
//                .password(passwordEncoder().encode("password1"))
//                .roles("USER")
//                .build();
//        UserDetails admin =  User.withUsername("admin")
//                .password(passwordEncoder().encode("demo"))
//                .roles("ADMIN")
//                .build();
//
//        JdbcUserDetailsManager userDetailsManager =  new JdbcUserDetailsManager(dataSource);
//        userDetailsManager.createUser(user1);
//        userDetailsManager.createUser(admin);
//        return userDetailsManager;
////        return new InMemoryUserDetailsManager(user1, admin);
//    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception{
        return builder.getAuthenticationManager();
    }

}
