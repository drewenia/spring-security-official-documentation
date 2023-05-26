# Anonymous Authentication

## Overview
Genel olarak, "deny-by-default" yaklaşımını benimsemek, her şeyin yasak olduğunu açıkça belirttiğiniz ve sadece izin 
verilenleri belirttiğiniz bir güvenlik uygulaması olarak kabul edilir. Kimliği doğrulanmamış kullanıcılar için 
erişilebilir olanları tanımlamak da benzer bir durumdur, özellikle web uygulamaları için. Birçok site, ana sayfa ve 
giriş sayfaları gibi birkaç URL dışında, kullanıcıların kimlik doğrulaması gerektiğini istemektedir. Bu durumda, 
özellikle her güvence altına alınmış kaynak için ayrı ayrı access configuration attributelarını tanımlamak yerine, 
belirli URL'ler için access configuration attribute'larını tanımlamak en kolayıdır. Başka bir deyişle, 
ROLE_SOMETHING'ın varsayılan olarak gerektirildiği ve yalnızca giriş, çıkış ve ana sayfa gibi belirli istisnalara 
izin verildiği bir kuralı uygulamak bazen tercih edilir. Ayrıca, bu sayfaları tamamen filter chain dışında bırakarak 
access control checks'leri atlamak da mümkündür, ancak bu, sayfaların kimlik doğrulanan kullanıcılar için farklı 
şekilde davranması durumunda başka nedenlerle istenmeyebilir. Bu, anonim kimlik doğrulamanın ne anlama geldiğini ifade 
etmektedir. Anonim kimlik doğrulaması yapılmış bir kullanıcı ile kimlik doğrulanmamış bir kullanıcı arasında gerçek bir 
kavramsal fark yoktur. Spring Security'nin anonim kimlik doğrulaması, erişim kontrol özniteliklerinizi daha uygun bir 
şekilde yapılandırmanızı sağlar. getCallerPrincipal gibi servlet API çağrıları, gerçekten SecurityContextHolder'da bir 
anonim kimlik doğrulama nesnesi bulunmasına rağmen hala null değeri döndürür. 

Anonim kimlik doğrulamanın kullanışlı olduğu diğer durumlar da vardır, örneğin auditing interceptor, hangi ilkenin 
belirli bir işlem için sorumlu olduğunu belirlemek için SecurityContextHolder'ı sorguladığı durumlar. Sınıflar, 
SecurityContextHolder'ın her zaman bir Authentication nesnesi içerdiğini ve hiçbir zaman null içermediğini bildiğinde 
daha sağlam bir şekilde oluşturulabilir. Bu durum, anonim kimlik doğrulama sağlandığında bile geçerlidir, çünkü bu 
durumda SecurityContextHolder içinde bir Authentication nesnesi bulunur. Bu şekilde sınıflar, null kontrolü yapmaktan 
kaçınarak daha güvenli bir şekilde tasarlanabilir.

## Configuration
Spring Security, HTTP yapılandırmasını kullandığınızda (Spring Security 3.0'da tanıtıldı) otomatik olarak anonim kimlik 
doğrulama desteği sağlar. Bu özelleştirilebilir veya devre dışı bırakılabilir ve bunu <anonymous> öğesini kullanarak 
yapabilirsiniz. Burada açıklanan bean'leri yapılandırmak için ayrıca ayarlama yapmanıza gerek yoktur, ancak geleneksel 
bean yapılandırmasını kullanıyorsanız bunları yapılandırmanız gerekebilir. Varsayılan yapılandırma, anonim kimlik 
doğrulamayı sorunsuz bir şekilde etkinleştirir ve işler.

Anonim kimlik doğrulama özelliğini sağlamak için üç sınıf birlikte çalışır. AnonymousAuthenticationToken, 
Authentication'nın bir uygulamasıdır ve anonim kullanıcıya uygulanan GrantedAuthority örneklerini depolar. Buna 
karşılık gelen AnonymousAuthenticationProvider, ProviderManager içine zincirlenir, böylece AnonymousAuthenticationToken 
örnekleri kabul edilir. Son olarak, AnonymousAuthenticationFilter, normal kimlik doğrulama mekanizmalarının ardından 
zincirlenir ve SecurityContextHolder'da mevcut bir Authentication yoksa otomatik olarak bir 
AnonymousAuthenticationToken ekler. Filtre ve kimlik sağlayıcı aşağıdaki gibi tanımlanır XML:
```
<bean id="anonymousAuthFilter"
	class="org.springframework.security.web.authentication.AnonymousAuthenticationFilter">
<property name="key" value="foobar"/>
<property name="userAttribute" value="anonymousUser,ROLE_ANONYMOUS"/>
</bean>

<bean id="anonymousAuthenticationProvider"
	class="org.springframework.security.authentication.AnonymousAuthenticationProvider">
<property name="key" value="foobar"/>
</bean>
```
Anahtar, filtre ve kimlik sağlayıcı arasında paylaşılır, böylece önceki tarafından oluşturulan tokenlar, son tarafından 
kabul edilir.

Burada anahtar özelliğinin gerçek bir güvenlik sağladığı düşünülmemelidir. Bu yalnızca bir bilgi işlem çalışmasıdır. 
Eğer bir AuthenticatingProvider içeren bir ProviderManager paylaşıyorsanız ve bir yetkilendirme istemcisinin 
(örneğin, RMI çağrılarıyla) Authentication nesnesini oluşturması mümkünse, kötü niyetli bir istemci kendi oluşturduğu 
AnonymousAuthenticationToken'ı (seçilen kullanıcı adı ve yetkilendirme listesi ile) gönderebilir. Anahtar tahmin 
edilebilir veya bulunabilirse, token anonim sağlayıcı tarafından kabul edilecektir. Bu normal kullanımda bir sorun 
değildir. Ancak RMI kullanıyorsanız, HTTP kimlik doğrulama mekanizmalarınız için kullandığınızı paylaşmak yerine 
anonim sağlayıcıyı içermeyen özelleştirilmiş bir ProviderManager kullanmalısınız.

userAttribute özelliği, usernameInTheAuthenticationToken,grantedAuthority[,grantedAuthority] biçiminde ifade edilir.
InMemoryDaoImpl'in userMap özelliği için de eşittir işaretinden sonra aynı sözdizimi kullanılır.

Daha önce açıklandığı gibi, anonim kimlik doğrulamanın yararı, aşağıdaki örnekte gösterildiği gibi, tüm URI modellerine 
güvenlik uygulanabilmesidir XML:
```
<bean id="filterSecurityInterceptor"
	class="org.springframework.security.web.access.intercept.FilterSecurityInterceptor">
<property name="authenticationManager" ref="authenticationManager"/>
<property name="accessDecisionManager" ref="httpRequestAccessDecisionManager"/>
<property name="securityMetadata">
	<security:filter-security-metadata-source>
	<security:intercept-url pattern='/index.jsp' access='ROLE_ANONYMOUS,ROLE_USER'/>
	<security:intercept-url pattern='/hello.htm' access='ROLE_ANONYMOUS,ROLE_USER'/>
	<security:intercept-url pattern='/logoff.jsp' access='ROLE_ANONYMOUS,ROLE_USER'/>
	<security:intercept-url pattern='/login.jsp' access='ROLE_ANONYMOUS,ROLE_USER'/>
	<security:intercept-url pattern='/**' access='ROLE_USER'/>
	</security:filter-security-metadata-source>" +
</property>
</bean>
```

## AuthenticationTrustResolver

Anonymous authentication hakkında konuşmayı tamamlamak için AuthenticationTrustResolver interfaceini ve buna karşılık 
gelen AuthenticationTrustResolverImpl uygulamasını ekleyelim. Bu interface, ilgili sınıfların bu özel türdeki kimlik 
doğrulama durumunu dikkate almasını sağlayan isAnonymous(Authentication) yöntemini sağlar. ExceptionTranslationFilter, 
AccessDeniedException örneklerini işlerken bu interface'i kullanır. Bir AccessDeniedException fırlatılırsa ve kimlik 
doğrulama anonim bir tür ise, filtrenin 403 (yoksayılmış) yanıtını fırlatmak yerine, filtre, AuthenticationEntryPoint'i 
başlatır ve bu şekilde kimlik doğrulama yapabilir. Bu gerekli bir ayrımı sağlar. Aksi takdirde, prensipler her zaman 
"kimlik doğrulanmış" olarak kabul edilir ve form, basic, digest veya diğer normal kimlik doğrulama mekanizmalarıyla 
oturum açma fırsatı verilmez.

Eski interceptor yapılandırmasında genellikle ROLE_ANONYMOUS attribute'unu IS_AUTHENTICATED_ANONYMOUSLY ile 
değiştirildiğini görüyoruz ve access controls tanımlarken etkili olarak aynı şeydir. Bu, yetkilendirme bölümünde ele 
aldığımız AuthenticatedVoter'ın kullanımına bir örnektir. Bu yaklaşım, AuthenticationTrustResolver kullanarak bu özel 
yapılandırma attribute'unu işler ve anonim kullanıcılara erişim izni verir. AuthenticatedVoter yaklaşımı, anonim, 
remember me ve tamamen kimlik doğrulanmış kullanıcılar arasında ayrım yapmanıza olanak tanır, bu nedenle daha güçlüdür. 
Ancak, bu işlevselliğe ihtiyacınız yoksa, Spring Security'nin standart RoleVoter tarafından işlenen ROLE_ANONYMOUS ile 
devam edebilirsiniz.

## Getting Anonymous Authentications with Spring MVC
Spring MVC, Principal türünde parametreleri kendi argument resolver'ini kullanarak çözer. Bu, Spring MVC'nin Principal 
türündeki parametreleri otomatik olarak çözebilmesi anlamına gelir. Yani, bir yöntemde Principal türünde bir parametre 
belirtildiğinde, Spring MVC bu parametreyi otomatik olarak çözer ve geçerli kullanıcı kimliğini içeren bir Principal 
nesnesini sağlar. Böylece, ilgili iş mantığı kodunda doğrudan Principal nesnesine erişebilirsiniz.
```
@GetMapping("/")
public String method(Authentication authentication) {
	if (authentication instanceof AnonymousAuthenticationToken) {
		return "anonymous";
	} else {
		return "not anonymous";
	}
}
```
anonim istekler için bile her zaman "non anonymous" döndürür. Bunun nedeni, Spring MVC'nin, istek anonim olduğunda 
null olan HttpServletRequest#getPrincipal'ı kullanarak parametreyi çözmesidir.

Kimlik Doğrulamayı anonim isteklerde almak istiyorsanız, bunun yerine @CurrentSecurityContext kullanın:
```
@GetMapping("/")
public String method(@CurrentSecurityContext SecurityContext context) {
	return context.getAuthentication().getName();
}
```