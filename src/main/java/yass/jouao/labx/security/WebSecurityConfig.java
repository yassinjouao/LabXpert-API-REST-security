package yass.jouao.labx.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import yass.jouao.labx.security.jwt.AuthEntryPointJwt;
import yass.jouao.labx.security.jwt.AuthTokenFilter;
import yass.jouao.labx.security.services.UserDetailsServiceImpl;

@Configuration
public class WebSecurityConfig {
	@Autowired
	UserDetailsServiceImpl userDetailsService;

	@Autowired
	private AuthEntryPointJwt unauthorizedHandler;

	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder());
		return authProvider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		return authConfig.getAuthenticationManager();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(csrf -> csrf.disable())
				.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authorizeHttpRequests(auth -> {
					auth.antMatchers("/auth/**").permitAll();
					auth.antMatchers("/analysis/**").hasAnyRole("ADMIN", "MANAGER");
					auth.antMatchers("/analysistype/**").hasAnyRole("ADMIN");
					auth.antMatchers("/fournisseur/**").hasAnyRole("MANAGER");
					auth.antMatchers("/patient/**").hasAnyRole("ADMIN");
					auth.antMatchers("/reagent/**").hasAnyRole("MANAGER");
					auth.antMatchers("/sample/**").hasAnyRole("TECHNICIAN");
					auth.antMatchers("/test/**").hasAnyRole("TECHNICIAN");
					auth.antMatchers("/test-type/**").hasAnyRole("ADMIN");
					auth.antMatchers("/user/**").hasAnyRole("ADMIN");

					auth.anyRequest().authenticated();
				});
		http.authenticationProvider(authenticationProvider());
		http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}
}
