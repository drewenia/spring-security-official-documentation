# Security HTTP Response Headers

Web uygulamalarının güvenliğini artırmak için Security HTTP Response Headers kullanabilirsiniz. Bu bölüm, Security HTTP
Response Headers'ın servlet tabanlı desteği için ayrılmıştır.

## Default Security Headers

Spring Security, güvenli varsayılanları sağlamak için bir dizi Security HTTP Response Headers sunar. Her biri en iyi
uygulama olarak kabul edilen bu header'ların hepsi için not edilmelidir ki tüm istemciler bu header'ları
kullanmamaktadır, bu nedenle ek test yapılması önerilir.

Belirli header'ları özelleştirebilirsiniz. Örneğin, varsayılanları kullanmak istiyor ancak X-Frame-Options için
SAMEORIGIN değerini belirtmek istiyorsanız şu şekilde yapabilirsiniz:

Customize Default Security Headers:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.frameOptions(frameOptions -> frameOptions
					.sameOrigin()
				)
			);
		return http.build();
	}
}
```

Varsayılanların eklenmesini istemiyorsanız ve hangi header'ların kullanılacağı konusunda açık kontrol istiyorsanız,
varsayılanları devre dışı bırakabilirsiniz. Aşağıdaki kod örneğinde bunu nasıl yapacağınız gösterilmiştir:

Spring Security'nin yapılandırmasını kullanıyorsanız, aşağıdaki kod sadece Cache Control header'ini ekler:

Customize Cache Control Headers:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				// do not use any default headers unless explicitly listed
				.defaultsDisabled()
				.cacheControl(withDefaults())
			);
		return http.build();
	}
}
```

Gerekirse, aşağıdaki yapılandırmayla tüm HTTP Güvenlik response header'larını devre dışı bırakabilirsiniz:

Disable All HTTP Security Headers:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers.disable());
		return http.build();
	}
}
```

## Cache Control

Spring Security, varsayılan olarak Cache Control header'larını içerir. Bu nedenle, ekstra bir yapılandırmaya ihtiyaç
duymadan Cache Control header'ları otomatik olarak eklenir. Bu sayede, web uygulamanızdaki önbellekleme davranışını
kontrol edebilir ve önbellekleme saldırılarına karşı koruma sağlayabilirsiniz.

Ancak, belirli response'ları önbelleğe almak isterseniz, uygulamanız Spring Security tarafından ayarlanan header'i
geçersiz kılmak için HttpServletResponse.setHeader(String, String) methodunu seçici olarak kullanabilir. Bunu yaparak,
CSS, JavaScript ve resimler gibi içeriğin doğru bir şekilde önbelleğe alınmasını sağlayabilirsiniz. Özel response'lar
için önbellekleme davranışını kontrol etmek istediğinizde bu yöntemi kullanabilirsiniz.

Spring Web MVC kullanırken, genellikle bunu yapılandırmanız içinde yaparsınız. Spring Referans belgelerinin "Static
Resources" bölümünde bunu nasıl yapacağınıza dair detaylı bilgi bulabilirsiniz. Bu bölümde, statik kaynakların (örneğin
CSS, JavaScript, resimler) önbelleğe alınmasıyla ilgili yapılandırma yöntemleri açıklanmaktadır. Bu yöntemleri
kullanarak, belirli kaynakları doğru bir şekilde önbelleğe alabilirsiniz.

Gerekirse, Spring Security'nin cache control'unu de, HTTP response header'larını da devre dışı bırakabilirsiniz.

Cache Control Disabled:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.cacheControl(cache -> cache.disable())
			);
		return http.build();
	}
}
```

## Content Type Options

Spring Security, varsayılan olarak Content-Type header'larını içerir. Ancak, devre dışı bırakabilirsiniz:

Content Type Options Disabled:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.contentTypeOptions(contentTypeOptions -> contentTypeOptions.disable())
			);
		return http.build();
	}
}
```

## HTTP Strict Transport Security (HSTS)

Spring Security varsayılan olarak Strict Transport Security (STS) header'ini sağlar. Ancak, sonuçları açıkça
özelleştirebilirsiniz. Aşağıdaki örnek, HSTS'yi açıkça belirtmektedir:

Strict Transport Security:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.httpStrictTransportSecurity(hsts -> hsts
					.includeSubDomains(true)
					.preload(true)
					.maxAgeInSeconds(31536000)
				)
			);
		return http.build();
	}
}
```

## X-Frame-Options

Spring Security, varsayılan olarak tarayıcılara X-Frame-Options kullanarak yansıtılan XSS (Cross-Site Scripting)
saldırılarını engellemelerini söyler. X-Frame-Options header'i, web uygulamalarının tarayıcı içerisindeki frame
veya iframe içinde yüklenmesini sınırlayan bir mekanizmadır.

Örneğin, aşağıdaki yapılandırma, Spring Security'nin artık tarayıcılara içeriği engelleme talimatı vermemesi gerektiğini
belirtir

X-Frame-Options: SAMEORIGIN :

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.frameOptions(frameOptions -> frameOptions
					.sameOrigin()
				)
			);
		return http.build();
	}
}
```

## X-XSS-Protection

Spring Security, varsayılan olarak tarayıcılara XSS (Cross-Site Scripting) denetleyicisini devre dışı bırakmasını
söyleyerek XSS saldırılarını engeller. Bu, tarayıcının XSS saldırılarını algılama ve engelleme yeteneğini
etkinleştirmesini engeller.

X-XSS-Protection Customization:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.xssProtection(xss -> xss
					.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
				)
			);
		return http.build();
	}
}
```

## Content Security Policy

Content Security Policy (CSP), tarayıcılara belirli bir web sayfasının hangi kaynaklara erişebileceğini belirtir ve
potansiyel güvenlik açıklarını azaltır. Ancak, CSP'nin içeriği uygulamaya ve kullanılan kaynaklara bağlı olarak değişir.
Bu nedenle, güvenlik politikasının nasıl olması gerektiğini belirlemek uygulama sahibinin sorumluluğundadır.

Aşağıdaki güvenlik politikasını göz önünde bulundurun: (HTML)

```
Content-Security-Policy: script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/
```

Yukarıdaki güvenlik politikası örneğine göre, CSP başlığını etkinleştirebilirsiniz:

Content Security Policy:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.contentSecurityPolicy(csp -> csp
					.policyDirectives("script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/")
				)
			);
		return http.build();
	}
}
```

Yalnızca CSP rapor başlığını etkinleştirmek için aşağıdaki yapılandırmayı sağlayın:

Content Security Policy Report Only:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.contentSecurityPolicy(csp -> csp
					.policyDirectives("script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/")
					.reportOnly()
				)
			);
		return http.build();
	}
}
```

## Referrer Policy

Spring Security varsayılan olarak Referrer Policy header'ini eklemiyor. Referrer Policy header'ini etkinleştirmek için
aşağıdaki yapılandırmayı kullanabilirsiniz:

Referrer Policy:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.referrerPolicy(referrer -> referrer
					.policy(ReferrerPolicy.SAME_ORIGIN)
				)
			);
		return http.build();
	}
}
```

## Feature Policy

Spring Security varsayılan olarak Feature Policy header'ini eklemiyor. Aşağıdaki gibi bir Feature-Policy header'i
ekleyebilirsiniz:

Feature-Policy Example:

```
Feature-Policy: geolocation 'self'
```

Önceki özellik politikası başlığını aşağıdaki yapılandırma ile etkinleştirebilirsiniz:

Feature-Policy:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.featurePolicy("geolocation 'self'")
			);
		return http.build();
	}
}
```

## Permission Policy

Spring Security varsayılan olarak Permission Policy Header eklememektedir. Aşağıdaki örnek, Permission Policy Headerını
etkinleştirmenizi sağlar:

Permission Policy Example:

```
Permissions-Policy: geolocation=(self)
```

Spring Security varsayılan olarak Permission Policy Headerını eklememektedir. Aşağıdaki örnek, Permission Policy
Headerını etkinleştirmenizi sağlar:

Permission Policy:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.permissionsPolicy(permissions -> permissions
					.policy("geolocation=(self)")
				)
			);
		return http.build();
	}
}
```

## Clear Site Data

Spring Security, varsayılan olarak Clear-Site-Data header'larini eklemez. Aşağıdaki Clear-Site-Data başlığını göz önünde
bulundurun:

Clear-Site-Data Example:

```
Clear-Site-Data: "cache", "cookies"
```

Oturum kapatma işleminden önce aşağıdaki yapılandırmayı kullanarak önceki başlığı gönderebilirsiniz:

Clear-Site-Data :

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.logout((logout) -> logout
                .addLogoutHandler(new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(CACHE, COOKIES)))
			);
		return http.build();
	}
}
```

## Custom Headers

Spring Security, uygulamanıza yaygın güvenlik header'larını eklemeyi kolaylaştıran mekanizmalara sahiptir. Bununla
birlikte, özel header'lar eklemek için de kullanabileceğiniz hook'lar sağlar.

### Static Headers

Uygulamanıza yerleşik olarak desteklenmeyen özel güvenlik header'larını enjekte etmek istediğiniz durumlar olabilir.
Aşağıdaki özel güvenlik header'ini dikkate alalım:

```
X-Custom-Security-Header: header-value
```

Verilen özel header'i, aşağıdaki yapılandırmayı kullanarak response'un header'larını ekleyebilirsiniz:

StaticHeadersWriter:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.addHeaderWriter(new StaticHeadersWriter("X-Custom-Security-Header","header-value"))
			);
		return http.build();
	}
}
```

### Headers Writer

İstediğiniz header'ları desteklemeyen namespace veya Java yapılandırması durumunda, özel bir HeadersWriter instance'ı
oluşturabilir veya HeadersWriter'ın özel bir implementasyonunu sağlayabilirsiniz.

Eğer X-Frame-Options'ı açıkça yapılandırmak isterseniz, özel bir XFrameOptionsHeaderWriter instance'i kullanarak
aşağıdaki yapılandırmayı yapabilirsiniz:

Headers Writer:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// ...
			.headers(headers -> headers
				.addHeaderWriter(new XFrameOptionsHeaderWriter(XFrameOptionsMode.SAMEORIGIN))
			);
		return http.build();
	}
}
```

### DelegatingRequestMatcherHeaderWriter

Bazı durumlarda, belirli request'ler için yalnızca bir header yazmak isteyebilirsiniz. Örneğin, yalnızca giriş sayfanızı
framed'a (çerçevelenme) karşı korumak isteyebilirsiniz. Bu durumu sağlamak için DelegatingRequestMatcherHeaderWriter
kullanabilirsiniz.

Aşağıdaki yapılandırma örneği, DelegatingRequestMatcherHeaderWriter'ı kullanarak belirli bir request için header yazmayı
göstermektedir:

DelegatingRequestMatcherHeaderWriter Java Configuration :

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		RequestMatcher matcher = new AntPathRequestMatcher("/login");
		DelegatingRequestMatcherHeaderWriter headerWriter =
			new DelegatingRequestMatcherHeaderWriter(matcher,new XFrameOptionsHeaderWriter());
		http
			// ...
			.headers(headers -> headers
				.frameOptions(frameOptions -> frameOptions.disable())
				.addHeaderWriter(headerWriter)
			);
		return http.build();
	}
}
```