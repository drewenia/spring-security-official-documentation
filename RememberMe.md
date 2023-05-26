# Remember-Me Authentication

Remember-me veya persistent-login yetkilendirmesi, web sitelerinin oturumlar arasında bir başlığın kimliğini 
hatırlayabilmesini ifade eder. Bu genellikle tarayıcıya bir cookie gönderilerek gerçekleştirilir, 
cookie sonraki oturumlarda algılanır ve otomatik oturum açmanın gerçekleşmesine neden olur. Spring Security, 
bu işlemlerin gerçekleşmesi için gerekli hook'ları sağlar ve iki concrete remember me implementasyonuna sahiptir.
Cookie tabanlı tokenlarının güvenliğini korumak için genellikle hashing işlemleri kullanılırken, veritabanı veya diğer 
kalıcı depolama mekanizmaları kullanılarak oluşturulan tokenlar saklanır.

Cookie tabanlı tokenlar, kullanıcının tarayıcısında saklanır ve her istekle birlikte sunucuya iletilir. Bu tokenlar, 
genellikle kullanıcının kimliğini ve oturumu hatırlamak için kullanılır. Ancak, tokenları doğrudan depolamak güvenlik 
riski oluşturabilir, bu nedenle güvenliği sağlamak için hashing işlemleri kullanılır. Tokenlar, sunucu tarafında karma 
işlemlerle şifrelenir ve karşılaştırılırken doğrulanır. Diğer yandan, veritabanı veya kalıcı depolama mekanizmaları 
kullanılarak oluşturulan tokenlar, genellikle daha karmaşık bir yapıya sahiptir. Bu tokenlar, kullanıcının kimliğini ve 
diğer ilgili bilgileri depolamak için veritabanında veya diğer kalıcı depolama alanlarında saklanır. Bu durumda, 
tokenlar doğrudan kullanıcının tarayıcısına gönderilmez, ancak sunucu tarafında depolanır ve yönetilir. Tokenlar, 
kullanıcı kimliğini doğrulamak için veritabanında karşılaştırılır ve kontrol edilir.

Note : Her iki implementasyonunda UserDetailsService gerektirdiğini unutmayın. ğer UserDetailsService kullanmayan bir 
authentication provider (örneğin, LDAP sağlayıcısı) kullanıyorsanız, bunun düzgün çalışması için SecurityContext'de 
ayrıca bir UserDetailsService bean'ine sahip olmanız gerekmektedir.

## Simple Hash-Based Token Approach
Bu yaklaşım, yararlı bir remember me stratejisi elde etmek için hashing kullanır. Özünde, başarılı interactive kimlik 
doğrulamanın ardından tarayıcıya bir cookie gönderilir ve cookie aşağıdaki şekilde oluşturulur:
```
base64(username + ":" + expirationTime + ":" + algorithmName + ":"
algorithmHex(username + ":" + expirationTime + ":" password + ":" + key))

username:          As identifiable to the UserDetailsService
password:          That matches the one in the retrieved UserDetails
expirationTime:    The date and time when the remember-me token expires, expressed in milliseconds
key:               A private key to prevent modification of the remember-me token
algorithmName:     The algorithm used to generate and to verify the remember-me token signature
```
RememberMe tokeni yalnızca belirtilen süre boyunca ve yalnızca kullanıcı adı, parola ve key değişmezse geçerlidir.
Özellikle, bu durumda bir güvenlik sorunu olabilir, çünkü yakalanmış bir remember-me token'ı, token'ın süresi dolana 
kadar herhangi bir kullanıcı aracılığıyla kullanılabilir. Bu durumda, bir saldırgan, başka bir kullanıcının 
remember-me token'ını ele geçirir ve bu token'ı kullanarak uygulamaya erişebilir. Bu nedenle, remember-me token'larının 
güvenliği için ek önlemler alınmalıdır. Bu Digest Authentication'dakiler ile aynı sorundur. Bir kullanıcı, bir 
remember-me token'ının ele geçirildiğini fark ettiğinde, şifrelerini kolayca değiştirerek ve hemen geçerli tüm 
remember-me token'larını iptal ederek önlem alabilir. Bu durumda, ele geçirilen token'lar geçersiz hale gelir ve 
saldırganlar bu token'ları kullanarak uygulamaya erişemezler.

Bazı önlemler şunları içerebilir:
* Remember-me token'larının süresinin kısa tutulması ve düzenli olarak yenilenmesi.
* Token'ların güçlü bir şekilde şifrelenmesi ve doğrulanması.
* Token'ların sadece güvenli bağlantılar üzerinden iletilmesi.
* Token'ların sadece güvenli bir şekilde saklanması, örneğin, güvenli bir veritabanında veya önbellekte.

Bu önlemler, remember-me token'larının kötüye kullanımını engellemek ve güvenliğini artırmak için önemlidir. 
Uygulamanızın güvenlik gereksinimlerine bağlı olarak, remember-me mekanizmasının güvenliğini sağlamak için uygun 
önlemleri almanız önemlidir.

## Persistence Token Approach
(Esas olarak, kullanıcı adı gereksiz yere açığa çıkmaması için cookies'de kullanıcı adı yer almaz. Bu yaklaşımı 
namespace yapılandırmasıyla kullanmak için bir veritabanı kaynağı referansı sağlayın. XML:
```
<http>
...
<remember-me data-source-ref="someDataSource"/>
</http>
```
Veritabanı, aşağıdaki SQL (veya eşdeğeri) kullanılarak oluşturulan bir persistan_logins tablosu içermelidir:
```
create table persistent_logins (username varchar(64) not null,
						series varchar(64) primary key,
						token varchar(64) not null,
						last_used timestamp not null)
```

## Remember-Me Interfaces and Implementations
RememberMe, usernamePasswordAuthenticationFilter ile birlikte kullanılır ve AbstractAuthenticationProcessingFilter 
üst sınıfındaki hooks lar aracılığıyla uygulanır. BasicAuthenticationFilter içerisinde de kullanılır.

Hooks, uygun zamanlarda concrete bir RememberMeServices çağırır. Aşağıdaki liste interface'i gösterir:
```
Authentication autoLogin(HttpServletRequest request, HttpServletResponse response);

void loginFail(HttpServletRequest request, HttpServletResponse response);

void loginSuccess(HttpServletRequest request, HttpServletResponse response,
	Authentication successfulAuthentication);
```
AbstractAuthenticationProcessingFilter'ın yalnızca loginFail() ve loginSuccess() yöntemlerini çağırdığına dikkat edin.
AutoLogin() methodu, SecurityContextHolder bir Kimlik Doğrulama içermediğinde, RememberMeAuthenticationFilter 
tarafından çağrılır. Bu interface, dolayısıyla, temel hatırlama benimseme uygulamasına yetkileme ile ilgili olaylar 
hakkında yeterli bilgilendirme sağlar ve bir aday web isteği herhangi bir cookies içerebilir ve hatırlanmak 
isteyebilirse uygulamaya yetkilendirme yapar. Bu tasarım, herhangi bir sayıda RememberMe implementasyon 
stratejisine izin verir.

### TokenBasedRememberMeServices
Bu implementasyon, Simple Hash-Based Token Yaklaşımı'nda açıklanan daha basit bir yaklaşımı destekler. 
TokenBasedRememberMeServices, RememberMeAuthenticationProvider tarafından işlenen bir RememberMeAuthenticationToken 
oluşturur. Bu kimlik doğrulama sağlayıcısı ile TokenBasedRememberMeServices arasında bir key paylaşılır.
TokenBasedRememberMeServices, ayrıca doğrulama karşılaştırması için kullanıcı adı ve şifreyi alabileceği bir 
UserDetailsService'e ihtiyaç duyar ve doğru GrantedAuthority örneklerini içeren RememberMeAuthenticationToken'ı 
oluşturabilir. TokenBasedRememberMeServices, cookies'in otomatik olarak temizlenmesi için LogoutFilter ile birlikte 
kullanılabilmesi için Spring Security'nin LogoutHandler arayüzünü de uygular. Varsayılan olarak, bu uygulama SHA-256 
algoritmasını kullanarak token imzasını şifrelemektedir. Token imzasını doğrulamak için algorithmName parametresinden 
alınan algoritma ayrıştırılıp kullanılır. algorithmName yoksa varsayılan eşleştirme algoritması olan SHA-256 
kullanılacaktır. Farklı algoritmalara signature ecoding ve signature mathching için farklı algoritmalar 
belirtebilirsiniz. Bu, kullanıcıların eski algoritmaları doğrulayabilmelerine olanak sağlarken güvenli bir şekilde 
farklı bir kodlama algoritmasına yükseltmelerini sağlar, eğer algorithmName parametresi mevcut değilse. Bunu yapmak 
için özelleştirilmiş TokenBasedRememberMeServices'inizi Bean olarak belirtebilir ve yapılandırmada kullanabilirsiniz.

```
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http, RememberMeServices rememberMeServices) throws Exception {
	http
			.authorizeHttpRequests((authorize) -> authorize
					.anyRequest().authenticated()
			)
			.rememberMe((remember) -> remember
				.rememberMeServices(rememberMeServices)
			);
	return http.build();
}

@Bean
RememberMeServices rememberMeServices(UserDetailsService userDetailsService) {
	RememberMeTokenAlgorithm encodingAlgorithm = RememberMeTokenAlgorithm.SHA256;
	TokenBasedRememberMeServices rememberMe = 
	            new TokenBasedRememberMeServices(myKey, userDetailsService, encodingAlgorithm);
	rememberMe.setMatchingAlgorithm(RememberMeTokenAlgorithm.MD5);
	return rememberMe;
}
```
RememberMe service'ini etkinleştirmek için bir application context'de aşağıdaki beans'ler gereklidir XML:
```
<bean id="rememberMeFilter" class=
"org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter">
<property name="rememberMeServices" ref="rememberMeServices"/>
<property name="authenticationManager" ref="theAuthenticationManager" />
</bean>

<bean id="rememberMeServices" class=
"org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices">
<property name="userDetailsService" ref="myUserDetailsService"/>
<property name="key" value="springRocks"/>
</bean>

<bean id="rememberMeAuthenticationProvider" class=
"org.springframework.security.authentication.RememberMeAuthenticationProvider">
<property name="key" value="springRocks"/>
</bean>
```
Remember to add the RememberMeServices uygulamanızı UsernamePasswordAuthenticationFilter.setRememberMeServices() 
özelliğine eklemeyi, AuthenticationManager.setProviders() listesine RememberMeAuthenticationProvider'ı dahil etmeyi ve 
RememberMeAuthenticationFilter'ı FilterChainProxy'e (genellikle UsernamePasswordAuthenticationFilter'dan hemen sonra) 
eklemeyi unutmayın.

### PersistentTokenBasedRememberMeServices
Bu sınıfı TokenBasedRememberMeServices ile aynı şekilde kullanabilirsiniz, ancak ayrıca tokenları depolamak için bir 
PersistentTokenRepository ile yapılandırılması gerekir.
* Yalnızca test amaçlı InMemoryTokenRepositoryImpl.
* Tokenları bir veritabanında depolayan JdbcTokenRepositoryImpl.