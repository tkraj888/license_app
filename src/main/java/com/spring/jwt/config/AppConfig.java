
package com.spring.jwt.config;

import com.spring.jwt.config.filter.CustomAuthenticationProvider;
import com.spring.jwt.config.filter.JwtTokenAuthenticationFilter;
import com.spring.jwt.config.filter.JwtUsernamePasswordAuthenticationFilter;
import com.spring.jwt.exception.CustomAccessDeniedHandler;
import com.spring.jwt.jwt.JwtConfig;
import com.spring.jwt.jwt.JwtService;
import com.spring.jwt.security.UserDetailsServiceCustom;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class AppConfig {

    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Autowired
    JwtConfig jwtConfig;

    @Autowired
    private JwtService jwtService;

    @Bean
    public JwtConfig jwtConfig() {
        return new JwtConfig();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceCustom();
    }

    @Autowired
    public void configGlobal(final AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(customAuthenticationProvider);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
        AuthenticationManager manager = builder.build();

        http.cors().configurationSource(corsConfigurationSource())
                .and()
                .csrf().disable()
                .formLogin().disable()
                .authorizeHttpRequests()
                .requestMatchers("/account/**").permitAll()
                .requestMatchers("/cars/**").permitAll()
                .requestMatchers("/booking/**").hasAnyAuthority("USER", "ADMIN","DEALER")
                .requestMatchers("/userProfilePhoto/**").permitAll()
                .requestMatchers("/photo/**").permitAll()
                .requestMatchers("/admin/**").hasAuthority("ADMIN")
                .requestMatchers("/user/**").hasAnyAuthority("USER", "ADMIN")
                .requestMatchers("/api/licenseList/getLicenseList").permitAll()
                .requestMatchers("/api/licenseList/**").hasAnyAuthority("ADMIN")
                .requestMatchers("/api/licenseOfCustomerController/getByMailID").permitAll()
                .requestMatchers("/api/licenseOfCustomerController/**").hasAnyAuthority("ADMIN")
                .requestMatchers("/api/customer/**").hasAnyAuthority("ADMIN")
//                .requestMatchers("/account/**").permitAll()
//                .requestMatchers("/cars/**").permitAll()
//                .requestMatchers("/booking/**").permitAll()
//                .requestMatchers("/userProfilePhoto/**").permitAll()
//                .requestMatchers("/photo/**").permitAll()
//                .requestMatchers("/user/**").permitAll()
//                .requestMatchers("/api/licenseList/getLicenseList").permitAll()
//                .requestMatchers("/api/licenseList/**").permitAll()
//                .requestMatchers("/api/customer/**").permitAll()
//                .requestMatchers("api/licenseOfCustomerController/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .authenticationManager(manager)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling()
                .authenticationEntryPoint((req, res, ex) -> res.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .accessDeniedHandler(new CustomAccessDeniedHandler())
                .and()
                .addFilterBefore(new JwtUsernamePasswordAuthenticationFilter(manager, jwtConfig, jwtService),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig, jwtService),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        return request -> {
            CorsConfiguration config = new CorsConfiguration();

            // Allowed origins
            config.setAllowedOrigins(Arrays.asList(
                    "https://www.dostenterprises.com",
                    "https://dostenterprises.com",
                    "https://dost02.dostenterprises.com",
                    "https://license01.netlify.app",
                    "https://licenceok.vercel.app",
                    "http://localhost:5173",
                    "http://localhost:5174",
                    "http://localhost:3000"
            ));

            config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
            config.setAllowedHeaders(Collections.singletonList("*"));
            config.setAllowCredentials(true);
            config.setExposedHeaders(Arrays.asList("Authorization"));
            config.setMaxAge(3600L);

            return config;
        };
    }
}


//package com.spring.jwt.config;
//
//import com.spring.jwt.config.filter.CustomAuthenticationProvider;
//import com.spring.jwt.config.filter.JwtTokenAuthenticationFilter;
//import com.spring.jwt.config.filter.JwtUsernamePasswordAuthenticationFilter;
//import com.spring.jwt.exception.CustomAccessDeniedHandler;
//import com.spring.jwt.jwt.JwtConfig;
//import com.spring.jwt.jwt.JwtService;
//import com.spring.jwt.security.UserDetailsServiceCustom;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.CorsConfigurationSource;
//
//import java.util.Arrays;
//import java.util.Collections;
//
//@Configuration
//@EnableWebSecurity
//public class AppConfig {
//
//    @Autowired
//    private CustomAuthenticationProvider customAuthenticationProvider;
//
//    @Autowired
//    JwtConfig jwtConfig;
//
//    @Autowired
//    private JwtService jwtService;
//
//    @Bean
//    public JwtConfig jwtConfig(){
//        return new JwtConfig();
//    }
//
//    @Bean
//    public BCryptPasswordEncoder passwordEncoder(){
//        return new BCryptPasswordEncoder();
//    }
//
//    @Bean
//    public UserDetailsService userDetailsService(){
//        return new UserDetailsServiceCustom();
//    }
//
//    @Autowired
//    public void configGlobal(final AuthenticationManagerBuilder auth){
//        auth.authenticationProvider(customAuthenticationProvider);
//    }
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
//
//        builder.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
//
//        AuthenticationManager manager = builder.build();
//
//        http
//                .cors().configurationSource(corsConfigurationSource())
//                .and()
//
////                .csrf().disable()
////                .formLogin().disable()
////                .authorizeHttpRequests()
////                .requestMatchers("/account/**").permitAll()
////                .requestMatchers("/cars/**").permitAll()
////                .requestMatchers("/booking/**").hasAnyAuthority("USER", "ADMIN","DEALER")
////                .requestMatchers("/userProfilePhoto/**").permitAll()
////                .requestMatchers("/photo/**").permitAll()
//////                .requestMatchers("/admin/**").hasAuthority("ADMIN")
////                .requestMatchers("/user/**").hasAnyAuthority("USER", "ADMIN")
////
////
////                .requestMatchers("/api/licenseList/getLicenseList").permitAll()
////                .requestMatchers("/api/licenseList/**").hasAnyAuthority("ADMIN")
////                .requestMatchers("/api/licenseOfCustomerController/getByMailID").permitAll()
//////                .requestMatchers("/api/licenseOfCustomerController/**").hasAnyAuthority("ADMIN")
////                //.requestMatchers("/api/customer/**").hasAnyAuthority("ADMIN")
////                .requestMatchers("/api/customer/**").hasAnyAuthority("ADMIN")
//
//                .csrf().disable()
//                .formLogin().disable()
//                .authorizeHttpRequests()
//                .requestMatchers("/account/**").permitAll()
//                .requestMatchers("/cars/**").permitAll()
//                .requestMatchers("/booking/**").permitAll()
//                .requestMatchers("/userProfilePhoto/**").permitAll()
//                .requestMatchers("/photo/**").permitAll()
////                .requestMatchers("/admin/**").hasAuthority("ADMIN")
//                .requestMatchers("/user/**").permitAll()
//                .requestMatchers("api/licenseOfCustomerController/**").permitAll()
//
//                .requestMatchers("/api/licenseList/getLicenseList").permitAll()
//                .requestMatchers("/api/licenseList/**").permitAll()
////                .requestMatchers("/api/licenseOfCustomerController/getByMailID").permitAll()
////                .requestMatchers("/api/licenseOfCustomerController/**").hasAnyAuthority("ADMIN")
//                //.requestMatchers("/api/customer/**").hasAnyAuthority("ADMIN")
//                .requestMatchers("/api/customer/**").permitAll()
//
//
//                .anyRequest().authenticated()
//                .and()
//                .authenticationManager(manager)
//                .sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .exceptionHandling()
//                .authenticationEntryPoint(
//                        ((request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
//                )
//                .accessDeniedHandler(new CustomAccessDeniedHandler())
//                .and()
//                .addFilterBefore(new JwtUsernamePasswordAuthenticationFilter(manager, jwtConfig, jwtService), UsernamePasswordAuthenticationFilter.class)
//                .addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig, jwtService), UsernamePasswordAuthenticationFilter.class)
//        ;
//        return http.build();
//    }
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        return request -> {
//            CorsConfiguration config = new CorsConfiguration();
//
//            config.setAllowedOrigins(Arrays.asList(
//                    "https://dost02.dostenterprises.com",   // 🔥 MUST ADD THIS
//                    "https://licenceok.vercel.app",
//                    "https://dostenterprises.com",
//                    "https://www.dostenterprises.com",
//                    "https://license01.netlify.app",
//                    "http://localhost:5174",
//                    "http://localhost:5173",
//                    "http://localhost:3000"
//            ));
//
//            config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
//            config.setAllowedHeaders(Collections.singletonList("*"));
//            config.setAllowCredentials(true);
//            config.setExposedHeaders(Arrays.asList("Authorization"));
//            config.setMaxAge(3600L);
//
//            return config;
//        };
////    @Bean
////    public CorsConfigurationSource corsConfigurationSource() {
////        return new CorsConfigurationSource() {
////            @Override
////            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
////                CorsConfiguration config = new CorsConfiguration();
////                config.setAllowedOrigins(Arrays.asList("https://licenceok.vercel.app","https://dostenterprises.com","https://www.dostenterprises.com","https://license01.netlify.app/","https://license01.netlify.app","http://localhost:5174","http://localhost:5173","http://localhost:3000"));
//////                config.setAllowedOrigins(Arrays.asList("https://license01.netlify.app/","https://license01.netlify.app"));
////                config.setAllowedMethods(Collections.singletonList("*"));
////                config.setAllowCredentials(true);
////                config.setAllowedHeaders(Collections.singletonList("*"));
////                config.setExposedHeaders(Arrays.asList("Authorization"));
////                config.setMaxAge(3600L);
////                return config;
////            }
////        };
//    }
//
//
//}
//
//
//
//
//
