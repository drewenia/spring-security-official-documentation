# Java Configuration

Spring Framework'a genel olarak Java yapılandırma desteği, Spring 3.1'de eklendi. Spring Security 3.2 ise XML
kullanmadan Spring Security'yi yapılandırmak için Java yapılandırmasını kullanıcıların kullanımına sundu.

Eğer Security Namespace Configuration'u biliyorsanız, Spring Security Java yapılandırmasıyla arasında birçok benzerlik
bulacağınızı göreceksiniz.

Note : Spring Security, Spring Security Java Configuration kullanımını göstermek için birçok örnek uygulama sunar.

## Hello Web Security Java Configuration

İlk adım, Spring Security Java Yapılandırmamızı oluşturmaktır. Yapılandırma, uygulama URL'lerini koruma, gönderilen
kullanıcı adı ve şifreleri doğrulama, oturum açma formuna yönlendirme vb. gibi tüm güvenlik işlemlerinden sorumlu olan
springSecurityFilterChain olarak bilinen bir Servlet Filtresi oluşturur. Aşağıdaki örnek, en temel bir Spring Security
Java Yapılandırmasını göstermektedir:

```
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.authentication.builders.*;
import org.springframework.security.config.annotation.web.configuration.*;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build());
		return manager;
	}
}
```

Bu yapılandırma karmaşık veya kapsamlı değildir, ancak çok şey yapar:

* Uygulamanızdaki her URL için kimlik doğrulaması gerektirin
* Sizin için bir giriş formu oluşturun
* Kullanıcı adı "user" ve şifre "password" olan kullanıcının form tabanlı authentication ile authenticate olmasına
  izin vermek için
* Kullanıcının logout olmasına izin ver
* CSRF Attack önleme
* Session Fixation koruması
* Security Header Integration
    * Spring Security ile güvenli request'ler için HTTP Strict Transport Security (HSTS) özelliğini etkinleştirmek için,
      httpStrictTransportSecurity yöntemini kullanabilirsiniz
    * Spring Security, X-Content-Type-Options entegrasyonunu kolaylaştırmak için otomatik olarak çalışır.
    * Spring Security, Cache Control entegrasyonunu kolaylaştırır. Varsayılan olarak, statik kaynaklarınızın önbelleğe
      alınmasına izin vermez ve response'ların önbelleğe alınmamasını sağlar.
    * X-XSS-Protection entegrasyonu
    * Clickjacking'i önlemeye yardımcı olmak için X-Frame-Options entegrasyonu
* Aşağıdaki Servlet API yöntemleriyle entegrasyon:
    * HttpServletRequest#getRemoteUser()
    * HttpServletRequest#getUserPrincipal()
    * HttpServletRequest#isUserInRole(java.lang.String)
    * HttpServletRequest#login(java.lang.String, java.lang.String)
    * HttpServletRequest#logout()

### AbstractSecurityWebApplicationInitializer

Spring Security'nin springSecurityFilterChain'ini WAR dosyasına kaydetmek için Java konfigürasyonunda Spring'in
WebApplicationInitializer desteğini kullanabilirsiniz. Bu, Servlet 3.0 ve üzeri bir ortamda gerçekleştirilebilir. Spring
Security, springSecurityFilterChain'in otomatik olarak kaydedilmesini sağlamak için kullanabileceğiniz
AbstractSecurityWebApplicationInitializer adlı bir temel sınıf sağlar. AbstractSecurityWebApplicationInitializer'ı
kullanma şeklimiz, Spring'i zaten kullanıp kullanmadığımıza veya Spring Security'nin uygulamamızdaki tek Spring bileşeni
olup olmadığına bağlı olarak değişir.

* Hali hazırda Spring kullanmıyor iseniz : Aşağıda detaylı bahsedilecek olan: "AbstractSecurityWebApplicationInitializer
  without Existing Spring" bölümüne bakınız
* Zaten Spring kullanıyorsanız bu bölüme bakın : "AbstractSecurityWebApplicationInitializer with Spring MVC"

### AbstractSecurityWebApplicationInitializer without Existing Spring

Spring veya Spring MVC kullanmıyorsanız, yapılandırmanın alındığından emin olmak için WebSecurityConfig'i üst sınıfa
iletmeniz gerekir:

```
import org.springframework.security.web.context.*;

public class SecurityWebApplicationInitializer
	extends AbstractSecurityWebApplicationInitializer {

	public SecurityWebApplicationInitializer() {
		super(WebSecurityConfig.class);
	}
}
```

SecurityWebApplicationInitializer :

* Uygulamanızdaki her URL için springSecurityFilterChain Filtresini otomatik olarak register eder.
* WebSecurityConfig'i yükleyen bir ContextLoaderListener ekleyin.

### AbstractSecurityWebApplicationInitializer with Spring MVC

Spring'i uygulamamızın başka bir yerinde kullanırsak, muhtemelen zaten Spring Configuration'ımızı yükleyen bir
WebApplicationInitializer'a sahibiz demektir. Eğer önceki yapılandırmayı kullanırsak, bir hata alırız. Bunun yerine,
mevcut ApplicationContext ile Spring Security'yi kaydetmeliyiz. Örneğin, Spring MVC kullanıyorsak,
SecurityWebApplicationInitializer şu şekilde görünebilir:

```
import org.springframework.security.web.context.*;

public class SecurityWebApplicationInitializer
	extends AbstractSecurityWebApplicationInitializer {

}
```

Bu sadece springSecurityFilterChain'i uygulamanızdaki her URL için kaydeder. Bundan sonra, mevcut
ApplicationInitializer'ımızda WebSecurityConfig'in yüklendiğinden emin olmamız gerekiyor. Örneğin, Spring MVC
kullanıyorsak, bunu getRootConfigClasses() metoduna ekleriz:

```
public class MvcWebApplicationInitializer extends
		AbstractAnnotationConfigDispatcherServletInitializer {

	@Override
	protected Class<?>[] getRootConfigClasses() {
		return new Class[] { WebSecurityConfig.class };
	}

	// ... other overrides ...
}
```

## HttpSecurity

WebSecurityConfig sınıfımız yalnızca kullanıcıları nasıl doğrulayacağımız hakkında bilgi içeriyor. Spring Security nasıl
biliyor ki tüm kullanıcıların authenticated olmasını istiyoruz? Spring Security, form based authentication desteklemek
istediğimizi nasıl biliyor? Aslında, arka planda çağrılan bir yapılandırma sınıfı (SecurityFilterChain adı verilen)
bulunur. Bu sınıf, aşağıdaki varsayılan implementasyon ile yapılandırılmıştır:

```
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	http
		.authorizeRequests(authorize -> authorize
			.anyRequest().authenticated()
		)
		.formLogin(withDefaults())
		.httpBasic(withDefaults());
	return http.build();
}
```

Default configuration (yukarıda ki örnekte gösterilmiştir)

* herhangi bir request yapıldığında kullanıcının authenticated olması gerekmektedir. Bu sayede, yetkilendirilmemiş
  kullanıcılar uygulama kaynaklarına erişim sağlayamazlar ve kimlik doğrulaması gerektiren işlemleri
  gerçekleştiremezler.
* Kullanıcıların form based login ile authenticate olmasını sağlar
* Kullanıcıların HTTP Basic authentication ile authenticate olmasını sağlar

Note : Bu yapılandırmanın, XML Namespace yapılandırmasıyla paralel olduğunu unutmayın: (XML)

```
<http>
	<intercept-url pattern="/**" access="authenticated"/>
	<form-login />
	<http-basic />
</http>
```

## Multiple HttpSecurity Instances

Birden fazla HttpSecurity instance'ini yapılandırabiliriz, XML'de birden fazla <http> bloğuna sahip olabileceğimiz gibi.
Anahtar nokta, birden çok SecurityFilterChain @Bean'ini kaydetmektir. Aşağıdaki örnek, /api/ ile başlayan URL'ler için
farklı bir yapılandırmaya sahiptir:

```
@Configuration
@EnableWebSecurity
public class MultiHttpSecurityConfig {
	@Bean (-1-)
	public UserDetailsService userDetailsService() throws Exception {
		// ensure the passwords are encoded properly
		UserBuilder users = User.withDefaultPasswordEncoder();
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(users.username("user").password("password").roles("USER").build());
		manager.createUser(users.username("admin").password("password").roles("USER","ADMIN").build());
		return manager;
	}

	@Bean
	@Order(1) (-2-)
	public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
		http
			.securityMatcher("/api/**") (-3-)
			.authorizeHttpRequests(authorize -> authorize
				.anyRequest().hasRole("ADMIN")
			)
			.httpBasic(withDefaults());
		return http.build();
	}

	@Bean (-4-)
	public SecurityFilterChain formLoginFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize -> authorize
				.anyRequest().authenticated()
			)
			.formLogin(withDefaults());
		return http.build();
	}
}
```

1 - Authentication'i her zaman ki gibi yapılandırın

2 - Önce hangi SecurityFilterChain'in dikkate alınması gerektiğini belirtmek için @Order içeren bir SecurityFilterChain
instance'ı oluşturun.

3 - http.securityMatcher, bu HttpSecurity'nin yalnızca /api/ ile başlayan URL'ler için geçerli olduğunu belirtir.

4 - SecurityFilterChain'in başka bir instance'ini oluşturun. URL /api/ ile başlamıyorsa bu yapılandırma kullanılır. Bu
yapılandırma, 1'den sonra bir @Order değerine sahip olduğu için apiFilterChain'den sonra dikkate alınır

## Custom DSL's

Spring Security'de kendi özel DSL'lerinizi sağlayabilirsiniz:

```
public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
	private boolean flag;

	@Override
	public void init(HttpSecurity http) throws Exception {
		// any method that adds another configurer
		// must be done in the init method
		http.csrf().disable();
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		// here we lookup from the ApplicationContext. You can also just create a new instance.
		MyFilter myFilter = context.getBean(MyFilter.class);
		myFilter.setFlag(flag);
		http.addFilterBefore(myFilter, UsernamePasswordAuthenticationFilter.class);
	}

	public MyCustomDsl flag(boolean value) {
		this.flag = value;
		return this;
	}

	public static MyCustomDsl customDsl() {
		return new MyCustomDsl();
	}
}
```

HttpSecurity.authorizeRequests() gibi methodlar genellikle Spring Security gibi güvenlik kütüphanelerinde kullanılır. Bu
method, gelen HTTP request'lerini yetkilendirme kurallarına göre işlemek için kullanılır.

Daha sonra custom DSL'yi kullanabilirsiniz:

```
@Configuration
@EnableWebSecurity
public class Config {
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.apply(customDsl())
				.flag(true)
				.and()
			...;
		return http.build();
	}
}
```

Kod aşağıdaki sırayla çağrılır:

* Config.configure methodunda ki kod çağrılır
* MyCustomDsl.init methodunda ki kod çağrılır
* MyCustomDsl.configure methodunda ki kod çağrılır

İsterseniz SpringFactories kullanarak HttpSecurity'nin varsayılan olarak MyCustomDsl eklemesini sağlayabilirsiniz.
Örneğin, META-INF/spring.factories adlı dosyası resource altina META-INF altına ekleyerek bir kaynak oluşturabilirsiniz

META-INF/spring.factories:

```
org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer = sample.MyCustomDsl
```

Varsayılanı daha sonra devre dışı bırakabilirsiniz:

```
@Configuration
@EnableWebSecurity
public class Config {
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.apply(customDsl()).disable()
			...;
		return http.build();
	}
}
```

## Post Processing Configured Objects

Spring Security'nin Java yapılandırması, güvenlik ayarlarını basit ve kullanıcı dostu bir şekilde sağlamayı hedefler. Bu
nedenle, her seçeneği veya özelliği açığa çıkarmak yerine, genellikle en yaygın olarak kullanılan ve genel olarak
ihtiyaç duyulan ayarları belirtmeyi tercih eder.

Her özelliği doğrudan açığa çıkarmamak için iyi nedenler olabilir. Bununla birlikte, kullanıcılar hala daha gelişmiş
yapılandırma seçeneklerine ihtiyaç duyabilir. Bu sorunu çözmek için, Spring Security Java yapılandırması tarafından
oluşturulan birçok nesneyi modify veya replace için ObjectPostProcessor kavramı tanıtılır. Örneğin,
FilterSecurityInterceptor üzerinde filterSecurityPublishAuthorizationSuccess özelliğini yapılandırmak için aşağıdakini
kullanabilirsiniz:

```
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	http
		.authorizeRequests(authorize -> authorize
			.anyRequest().authenticated()
			.withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
				public <O extends FilterSecurityInterceptor> O postProcess(
						O fsi) {
					fsi.setPublishAuthorizationSuccess(true);
					return fsi;
				}
			})
		);
	return http.build();
}
```