package com.example.testsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {

        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();

        hierarchy.setHierarchy("ROLE_C > ROLE_B\n" +
                "ROLE_B > ROLE_A");

        return hierarchy;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login", "/loginProc", "/join", "/joinProc")
                        .permitAll()    // 모든 사용자에게 로그인을 하지 않아도 접근할 수 있도록 설정
                        .requestMatchers("/admin")  // admin 경로에 대해 설정
                        .hasRole("ADMIN")   // 특정 Role을 가진 사용자만 접근할 수 있도록 설정
                        .requestMatchers("/my/**")  // my페이지의 모든 하위 페이지
                        .hasAnyRole("ADMIN", "USER")    // 여러 가지 Role을 가진 사용자들이 접근할 수 있도록 설정
                        .anyRequest().authenticated()
                );

//        http
//                // 자동으로 /login 페이지로 redirect해줌
//                .formLogin((auth) -> auth.loginPage("/login")
//                        // 로그인 처리를 할 URL인듯, Security가 알아서 처리한대
//                        .loginProcessingUrl("/loginProc")
//                        // 로그인 페이지는 아무나 들어올 수 있게 permitAll() 처리
//                        .permitAll()
//                );
        http
                .httpBasic(Customizer.withDefaults());

//        http
                // 사이트 위, 변조 방지 시스템, 추후에 설정할 예정
                // default는 enable이므로 주석처리하면 된다.
//                .csrf((auth) -> auth.disable());

        http
                .sessionManagement((auth) -> auth
                        .maximumSessions(1) // 하나의 ID에 대해 최대로 허용하는 동시 접속 로그인 수
                        .maxSessionsPreventsLogin(true));   // 최대 동시 접속 수를 초과하는 경우에 대한 처리

        http
                .sessionManagement((auth) -> auth
                        .sessionFixation()
                        .changeSessionId());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails user1 = User.builder()
                .username("user1")
                .password(bCryptPasswordEncoder().encode("1234"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user1);
    }
}
