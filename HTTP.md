# HTTP

Tüm HTTP tabanlı iletişim TLS kullanılarak korunmalıdır.

Bu bölüm, HTTPS kullanımına yardımcı olan servlet özel özelliklerinin ayrıntılarını tartışmaktadır.

## Redirect to HTTPS

Bir client, HTTPS yerine HTTP kullanarak bir request'de bulunursa, Spring Security'yi HTTPS'ye yönlendirmek için
yapılandırabilirsiniz.

Örneğin, aşağıdaki Java veya Kotlin yapılandırması, tüm HTTP isteklerini HTTPS'ye yönlendirir:

Redirect to HTTPS:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.requiresChannel(channel -> channel
				.anyRequest().requiresSecure()
			);
		return http.build();
	}
}
```

Aşağıdaki XML yapılandırması, tüm HTTP isteklerini HTTPS'ye yönlendirir (XML):

Redirect to HTTPS with XML Configuration:

```
<http>
	<intercept-url pattern="/**" access="ROLE_USER" requires-channel="https"/>
...
</http>
```

## Strict Transport Security

Spring Security, Strict Transport Security için destek sağlar ve bunu varsayılan olarak etkinleştirir.

## Proxy Server Configuration

Spring Security, proxy sunucularıyla integrate olur.