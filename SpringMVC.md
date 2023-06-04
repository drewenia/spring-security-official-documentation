# Spring MVC Integration

Spring Security, Spring MVC ile bir dizi isteğe bağlı entegrasyon sağlar. Bu bölüm, entegrasyonu daha ayrıntılı bir
şekilde ele almaktadır.

## @EnableWebMvcSecurity

Spring Security 4.0'dan itibaren, @EnableWebMvcSecurity kullanımı deprecate edilmiştir. Bunun yerine, classpath'e
dayalı olarak Spring MVC özelliklerini ekleyen @EnableWebSecurity kullanılmalıdır.

Spring MVC ile Spring Security entegrasyonunu etkinleştirmek için yapılandırmanıza @EnableWebSecurity annotation'ını
ekleyin.

Spring Security, Spring MVC'nin WebMvcConfigurer'ını kullanarak yapılandırmayı sağlar. Bu, WebMvcConfigurationSupport
ile doğrudan entegrasyon gibi daha gelişmiş seçenekleri kullanıyorsanız, Spring Security yapılandırmasını manuel olarak
sağlamanız gerektiği anlamına gelir.

## MvcRequestMatcher

Spring Security, Spring MVC'nin MvcRequestMatcher ile URL'leri eşleştirme konusunda derin entegrasyon sağlar. Bu,
Güvenlik kurallarınızın request'leri handle etmek için kullanılan mantığa uyduğundan emin olmanıza yardımcı olur.

MvcRequestMatcher'ı kullanmak için, Spring Security yapılandırmasını DispatcherServlet'in bulunduğu aynı
ApplicationContext'e yerleştirmeniz gerekir. Bu, Spring Security'nin MvcRequestMatcher'ın eşleştirmeyi gerçekleştirmek
için kullanılan ismi mvcHandlerMappingIntrospector olan bir HandlerMappingIntrospector bean'inin Spring MVC
yapılandırmanız tarafından kaydedilmesini beklediği için gereklidir.

web.xml dosyası, bu, yapılandırmanızı DispatcherServlet.xml dosyasına yerleştirmeniz gerektiği anlamına gelir: (XML)

```
<listener>
  <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
</listener>

<!-- All Spring Configuration (both MVC and Security) are in /WEB-INF/spring/ -->
<context-param>
  <param-name>contextConfigLocation</param-name>
  <param-value>/WEB-INF/spring/*.xml</param-value>
</context-param>

<servlet>
  <servlet-name>spring</servlet-name>
  <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
  <!-- Load from the ContextLoaderListener -->
  <init-param>
    <param-name>contextConfigLocation</param-name>
    <param-value></param-value>
  </init-param>
</servlet>

<servlet-mapping>
  <servlet-name>spring</servlet-name>
  <url-pattern>/</url-pattern>
</servlet-mapping>
```

Aşağıdaki WebSecurityConfiguration, DispatcherServlet'in ApplicationContext'ine yerleştirilmelidir:

```
public class SecurityInitializer extends
    AbstractAnnotationConfigDispatcherServletInitializer {

  @Override
  protected Class<?>[] getRootConfigClasses() {
    return null;
  }

  @Override
  protected Class<?>[] getServletConfigClasses() {
    return new Class[] { RootConfiguration.class,
        WebMvcConfiguration.class };
  }

  @Override
  protected String[] getServletMappings() {
    return new String[] { "/" };
  }
}
```

Note : Yetkilendirme kurallarını HttpServletRequest ve metod güvenliği üzerinde eşleştirerek sağlamanızı her zaman
tavsiye ederiz.

HttpServletRequest üzerinde eşleme yaparak yetkilendirme kuralları sağlamak, çok erken bir aşamada gerçekleştiği ve
saldırı yüzeyini azaltmaya yardımcı olduğu için iyidir. Method güvenliği, birisi web yetkilendirme kurallarını atlamış
olsa bile uygulamanızın hala güvende olmasını sağlar. Bu, Defence in Depth olarak bilinir.

Aşağıdaki gibi eşleştirilmiş bir controller düşünelim:

```
@RequestMapping("/admin")
public String admin() {
	// ...
}
```

Bu controller yöntemine sadece yönetici kullanıcılara erişimi sınırlamak için, HttpServletRequest üzerinde eşleme
yaparak yetkilendirme kuralları sağlayabilirsiniz. Aşağıdaki gibi:

```
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	http
		.authorizeHttpRequests((authorize) -> authorize
			.requestMatchers("/admin").hasRole("ADMIN")
		);
	return http.build();
}
```

Aşağıdaki liste, XML'de aynı şeyi yapar: (XML)

```
<http>
	<intercept-url pattern="/admin" access="hasRole('ADMIN')"/>
</http>
```

Her iki yapılandırmada da, "/admin" URL'si, kimlik doğrulaması yapılmış kullanıcının yönetici kullanıcı olmasını
gerektirir. Ancak, Spring MVC yapılandırmanıza bağlı olarak, "/admin.html" URL'si de "admin()" methodunuza eşlenebilir.
Ayrıca, Spring MVC yapılandırmanıza bağlı olarak, "/admin" URL'si de "admin()" methodunuza eşlenebilir.

Sorun, güvenlik kuralımızın yalnızca /admin'i korumasıdır. Spring MVC'nin tüm olası kombinasyonları için ek kurallar
ekleyebiliriz, ancak bu oldukça ayrıntılı ve zahmetli olabilir.

Neyse ki, requestMatchers DSL yöntemini kullandığınızda, Spring Security otomatik olarak bir MvcRequestMatcher
oluşturur, eğer Spring MVC'nin classpath'inde bulunduğunu tespit ederse. Bu nedenle, Spring MVC'nin URL'ye eşleme yapmak
için kullandığı aynı URL'leri Spring Security de koruyacaktır.

Spring MVC kullanırken yaygın bir gereklilik, servlet path özelliğini belirtmektir. Bunun için aynı servlet path'i
paylaşan birden fazla MvcRequestMatcher instance'i oluşturmak için MvcRequestMatcher.Builder'ı kullanabilirsiniz.

```
@Bean
public SecurityFilterChain filterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
	MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector).servletPath("/path");
	http
		.authorizeHttpRequests((authorize) -> authorize
			.requestMatchers(mvcMatcherBuilder.pattern("/admin")).hasRole("ADMIN")
			.requestMatchers(mvcMatcherBuilder.pattern("/user")).hasRole("USER")
		);
	return http.build();
}
```

Aşağıdaki XML aynı etkiye sahiptir:

```
<http request-matcher="mvc">
	<intercept-url pattern="/admin" access="hasRole('ADMIN')"/>
</http>
```

## @AuthenticationPrincipal

Spring Security, Spring MVC argümanları için geçerli Authentication.getPrincipal() değerini otomatik olarak çözebilen
AuthenticationPrincipalArgumentResolver'ı sağlar. @EnableWebSecurity'yi kullandığınızda, bu otomatik olarak Spring MVC
yapılandırmanıza eklenir. XML tabanlı yapılandırma kullanıyorsanız, bunu kendiniz eklemeniz gerekir. (XML)

```
<mvc:annotation-driven>
		<mvc:argument-resolvers>
				<bean class="org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver" />
		</mvc:argument-resolvers>
</mvc:annotation-driven>
```

AuthenticationPrincipalArgumentResolver'ı doğru bir şekilde yapılandırdıktan sonra, Spring MVC katmanında tamamen Spring
Security'den bağımsız çalışabilirsiniz.

Öyle bir durumu düşünelim ki, özel bir UserDetailsService örneği UserDetails interface'ini ve kendi CustomUser nesnesini
uygulayan bir nesne döndürüyor. Mevcut kimlik doğrulanmış kullanıcının CustomUser nesnesine aşağıdaki kodu kullanarak
erişilebilir:

```
@RequestMapping("/messages/inbox")
public ModelAndView findMessagesForUser() {
	Authentication authentication =
	SecurityContextHolder.getContext().getAuthentication();
	CustomUser custom = (CustomUser) authentication == null ? null : authentication.getPrincipal();

	// .. find messages for this user and return them ...
}
```

Spring Security 3.2'den itibaren, argümanı daha doğrudan bir şekilde çözebiliriz. Bunun için bir annotation eklememiz
gerekmektedir:

```
import org.springframework.security.core.annotation.AuthenticationPrincipal;

// ...

@RequestMapping("/messages/inbox")
public ModelAndView findMessagesForUser(@AuthenticationPrincipal CustomUser customUser) {

	// .. find messages for this user and return them ...
}
```

Bazı durumlarda, principal'i belirli bir şekilde dönüştürmeniz gerekebilir. Örneğin, CustomUser nesnesi final olarak
tanımlanmışsa, extend edilemez. Bu durumda, UserDetailsService, UserDetails interface'ini uygulayan ve CustomUser'a
erişmek için getCustomUser adında bir method sağlayan bir nesne döndürebilir. Aşağıdaki gibi:

```
public class CustomUserUserDetails extends User {
		// ...
		public CustomUser getCustomUser() {
				return customUser;
		}
}
```

CustomUser nesnesine, Authentication.getPrincipal() expression'ını kullanarak SpEL expression'ı ile erişebiliriz. İşte
bir örnek:

```
import org.springframework.security.core.annotation.AuthenticationPrincipal;

// ...

@RequestMapping("/messages/inbox")
public ModelAndView findMessagesForUser(@AuthenticationPrincipal(expression = "customUser") CustomUser customUser) {

	// .. find messages for this user and return them ...
}
```

SpEL expression'larında aynı zamanda bean'lere de başvurabiliriz. Örneğin, kullanıcılarımızı yönetmek için JPA
kullanıyorsak ve mevcut kullanıcının bir attribute'unu değiştirmek ve kaydetmek istiyorsak aşağıdaki gibi
kullanabiliriz:

```
import org.springframework.security.core.annotation.AuthenticationPrincipal;

// ...

@PutMapping("/users/self")
public ModelAndView updateName(@AuthenticationPrincipal(expression = "@jpaEntityManager.merge(#this)") CustomUser attachedCustomUser,
		@RequestParam String firstName) {

	// change the firstName on an attached instance which will be persisted to the database
	attachedCustomUser.setFirstName(firstName);

	// ...
}
```

Spring Security'e olan bağımlılığımızı daha da azaltmak için @AuthenticationPrincipal'ü kendi anatasyonumuz üzerinde bir
meta-anatasyon olarak kullanabiliriz. Aşağıdaki örnek, @CurrentUser adlı bir anatasyon üzerinde bunu nasıl
yapabileceğimizi göstermektedir:

```
@Target({ElementType.PARAMETER, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@AuthenticationPrincipal
public @interface CurrentUser {}
```

Spring Security bağımlılığını tek bir dosyaya izole ettik. Şimdi, @CurrentUser belirtildiğinde, mevcut kimlik
doğrulanmış kullanıcının CustomUser nesnesini çözmek için kullanabiliriz:

```
@RequestMapping("/messages/inbox")
public ModelAndView findMessagesForUser(@CurrentUser CustomUser customUser) {

	// .. find messages for this user and return them ...
}
```

## Spring MVC Async Integration

Spring Web MVC 3.2+ Asynchronous Request Processing için mükemmel bir destek sunmaktadır. Ek yapılandırma yapmadan,
Spring Security otomatik olarak controllerlardan dönen bir Callable'ı çağıran Thread'e SecurityContext'i set eder.
Örneğin, aşağıdaki method, Callable oluşturulduğunda mevcut olan SecurityContext ile çağrılır:

```
@RequestMapping(method=RequestMethod.POST)
public Callable<String> processUpload(final MultipartFile file) {

return new Callable<String>() {
	public Object call() throws Exception {
	// ...
	return "someView";
	}
};
}
```

Daha teknik bir ifadeyle söylemek gerekirse, Spring Security, WebAsyncManager ile entegre çalışır. Callable'ı işlemek
için kullanılan SecurityContext, startCallableProcessing çağrıldığında SecurityContextHolder'da bulunan SecurityContext'
tir.

Controller'lar tarafından döndürülen DeferredResult ile otomatik entegrasyon bulunmamaktadır. Bu, DeferredResult'in
kullanıcılar tarafından işlendiği ve dolayısıyla otomatik olarak entegre edilebilecek bir yol olmadığı anlamına gelir.
Bununla birlikte, Concurrency Support kullanarak Spring Security ile şeffaf bir entegrasyon sağlamak hala
mümkündür.

## Spring MVC and CSRF Integration

Spring Security, Spring MVC ile entegre olarak CSRF koruması ekler.

### Automatic Token Inclusion

Spring Security, Spring MVC form tag kullanan formların içine CSRF Token'ı otomatik olarak ekler. Aşağıdaki JSP
örneğini düşünelim: (XML)

```
<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page"
	xmlns:c="http://java.sun.com/jsp/jstl/core"
	xmlns:form="http://www.springframework.org/tags/form" version="2.0">
	<jsp:directive.page language="java" contentType="text/html" />
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
	<!-- ... -->

	<c:url var="logoutUrl" value="/logout"/>
	<form:form action="${logoutUrl}"
		method="post">
	<input type="submit"
		value="Log out" />
	<input type="hidden"
		name="${_csrf.parameterName}"
		value="${_csrf.token}"/>
	</form:form>

	<!-- ... -->
</html>
</jsp:root>
```

Önceki örnekte, aşağıdaki gibi bir HTML çıktısı üretilir:

```
<!-- ... -->

<form action="/context/logout" method="post">
<input type="submit" value="Log out"/>
<input type="hidden" name="_csrf" value="f81d4fae-7dec-11d0-a765-00a0c91e6bf6"/>
</form>

<!-- ... -->
```

### Resolving the CsrfToken

Spring Security, Spring MVC argümanları için mevcut CsrfToken'ı otomatik olarak çözebilen CsrfTokenArgumentResolver
sağlar. @EnableWebSecurity kullanarak, Spring MVC yapılandırmanıza bunu otomatik olarak eklersiniz. XML tabanlı
yapılandırma kullanıyorsanız, bunu kendiniz eklemeniz gerekmektedir.

CsrfTokenArgumentResolver uygun şekilde yapılandırıldıktan sonra, CsrfToken'ı statik HTML tabanlı uygulamanıza
açabilirsiniz:

```
@RestController
public class CsrfController {

	@RequestMapping("/csrf")
	public CsrfToken csrf(CsrfToken token) {
		return token;
	}
}
```

CsrfToken'ı diğer alanlardan gizli tutmak önemlidir. Bu, Cross Origin Sharing (CORS) kullanıyorsanız, CsrfToken'ı harici
alanlara açmamanız gerektiği anlamına gelir.