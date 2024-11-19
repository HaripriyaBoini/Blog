package com.springboot.blog.config;


import com.springboot.blog.security.JwtAuthenticationFilter;
import com.springboot.blog.utils.JWTAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {
    private  UserDetailsService userDetailService;

private JWTAuthenticationEntryPoint authenticationEntryPoint;
    private JwtAuthenticationFilter authenticationFilter;
    public SecurityConfig(UserDetailsService userDetailService,
                          JWTAuthenticationEntryPoint authenticationEntryPoint,
    JwtAuthenticationFilter authenticationFilter) {
        this.userDetailService = userDetailService;
        this.authenticationEntryPoint=authenticationEntryPoint;
        this.authenticationFilter=authenticationFilter;
    }

    @Bean
   public  PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{
        return configuration.getAuthenticationManager();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

//http.csrf().disable()
//        .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated()
//        ).httpBasic(Customizer.withDefaults());

        http.csrf().disable()
                .authorizeHttpRequests((authorize)->
                        authorize.requestMatchers(HttpMethod.GET,"/api/**").permitAll()
                                .requestMatchers("/api/auth/**").permitAll()


                        .anyRequest().authenticated()
                ).exceptionHandling(exception->exception
                        .authenticationEntryPoint(authenticationEntryPoint)
                )
                .sessionManagement(session->session.
                        sessionCreationPolicy(SessionCreationPolicy.STATELESS)    //SESSION STATE means share varables between reruns for each user session

                );
        http.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();

    }
//    @Bean
//    public UserDetailsService userDetailService(){
//        UserDetails ramesh= User.builder()
//                .username("ramesh")
//                .password(passwordEncoder().encode("ramesh"))
//                .roles("USER")
//                .build();
//
//        UserDetails admin=User.builder()
//                .username("ramesh")
//                .password(passwordEncoder().encode("admin"))
//                .roles("ADMIN")
//                .build();
//
//                return new InMemoryUserDetailsManager(ramesh,admin);
//    }


}
