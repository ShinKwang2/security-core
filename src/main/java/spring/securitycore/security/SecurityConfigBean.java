package spring.securitycore.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import spring.securitycore.security.service.CustomUserDetailsService;

import javax.sql.DataSource;

//@Configuration
//@EnableWebSecurity
public class SecurityConfigBean {

    /**
     * 직접 인증을 정의하고 싶다면 UserDetailsService 를 구현하여 Bean 으로 등록하면 된다.
     * 다만 여기선 @Serivce 를 통해 @Component 를 해주었다.
     */
//    @Bean
//    CustomUserDetailsService customUserDetailsService() {
//        return new CustomUserDetailsService();
//    }

//    @Bean
    public InMemoryUserDetailsManager userDetailsService() {

        String password = passwordEncoder().encode("1111");

        UserDetails user = User.withUsername("user")
                .password(password)
                .roles("USER")
                .build();

        UserDetails manager = User.withUsername("manager")
                .password(password)
                .roles("MANAGER", "USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(password)
                .roles("ADMIN", "MANAGER", "USER")
                .build();

        return new InMemoryUserDetailsManager(user, manager, admin);
    }

//    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

//    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .authorizeRequests()
                .antMatchers("/", "/users").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()

        .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .defaultSuccessUrl("/")
                .permitAll();

        return http.build();
    }

//    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
}
