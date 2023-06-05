# CORS

Spring Framework, CORS (Cross-Origin Resource Sharing) için birinci sınıf destek sağlar. CORS işlemi, Spring
Security'den önce gerçekleştirilmelidir, çünkü pre-flight request'i herhangi bir cookie içermez (örneğin,
JSESSIONID). Eğer istek cookie içermiyorsa ve Spring Security ilk sırada ise, istek kullanıcının kimlik doğrulamasının
yapılmadığı (çünkü istekte cookie bulunmadığı) sonucuna varır ve isteği reddeder.

CORS işlemlerinin öncelikli olarak ele alınmasını sağlamanın en kolay yolu CorsFilter kullanmaktır. Kullanıcılar,
aşağıdaki öğeleri kullanan CorsConfigurationSource sağlayarak CorsFilter'ı Spring Security ile entegre edebilir:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// by default uses a Bean by the name of corsConfigurationSource
			.cors(withDefaults())
			...
		return http.build();
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("https://example.com"));
		configuration.setAllowedMethods(Arrays.asList("GET","POST"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}
```

Aşağıdaki liste, XML'de aynı şeyi yapar: (XML)

```
<http>
	<cors configuration-source-ref="corsSource"/>
	...
</http>
<b:bean id="corsSource" class="org.springframework.web.cors.UrlBasedCorsConfigurationSource">
	...
</b:bean>
```

Spring MVC'nin CORS desteğini kullanıyorsanız, CorsConfigurationSource belirtmeyi atlayabilirsiniz ve Spring Security,
Spring MVC'ye sağlanan CORS yapılandırmasını kullanır.

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// if Spring MVC is on classpath and no CorsConfigurationSource is provided,
			// Spring Security will use CORS configuration provided to Spring MVC
			.cors(withDefaults())
			...
		return http.build();
	}
}
```

Aşağıdaki liste, XML'de aynı şeyi yapar: (XML)

```
<http>
	<!-- Default to Spring MVC's CORS configuration -->
	<cors />
	...
</http>
```