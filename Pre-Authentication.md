# Pre-Authentication Scenarios

Örnekler arasında X.509, Siteminder ve uygulamanın çalıştığı Java EE konteyneri tarafından sağlanan kimlik doğrulama
yer alır. Pre-Authentication kullanırken, Spring Security'nin yapması gereken işlemler şunlardır:

1 - Gelen isteği doğrulama sürecine yönlendirme: Pre-authentication kullanılıyorsa, gelen istek, kimlik doğrulama
sürecine yönlendirilir. Bu, önceden yapılandırılmış bir mekanizmanın (örneğin, konteyner tarafından sağlanan)
kimlik doğrulama verilerini sağlaması gerektiği anlamına gelir.

2 - Kimlik doğrulama verilerinin alınması: Pre-authentication mekanizması, kimlik doğrulama verilerini sağlar. Örneğin,
X.509 sertifikası kullanılıyorsa, sunucu X.509 sertifikasını alır ve doğrulama için kullanılır.

3 - Kimlik doğrulama işleminin gerçekleştirilmesi: Alınan kimlik doğrulama verileri kullanılarak, Spring Security
kimlik doğrulama işlemini gerçekleştirir. Bu, kullanıcının kimliğini doğrulamak ve kullanıcıya ilişkin bir kimlik
(Authentication) nesnesi oluşturmak anlamına gelir.

4 - Kimlik doğrulama sonuçlarının işlenmesi: Kimlik doğrulama işlemi tamamlandıktan sonra, Spring Security doğrulama
sonuçlarını işler. Bu, kimlik doğrulama başarılıysa kullanıcıya erişim izni verilmesini veya kimlik doğrulamanın
başarısız olduğu durumlarda uygun hata işleme sürecini tetiklemeyi içerir.

* İstekte bulunan kullanıcıyı tanımlayın
* Kullanıcı için yetkileri edinin

Detaylar, harici kimlik doğrulama mekanizmasına bağlıdır. X.509 örneğinde kullanıcı, sertifika bilgileriyle
tanımlanabilirken, Siteminder örneğinde HTTP isteği başlığıyla tanımlanabilir. Konteyner kimlik doğrulamasına
güvenildiğinde, kullanıcı gelen HTTP isteği üzerinde getUserPrincipal() metodunu çağırarak tanımlanır. Bazı durumlarda,
harici mekanizma kullanıcı için rol ve yetki bilgilerini sağlayabilir. Ancak diğer durumlarda, yetkileri kullanıcıya
ilişkin ayrı bir kaynaktan (örneğin, UserDetailsService gibi) almanız gerekebilir.

## Pre-Authentication Framework Classes

Çoğu Pre-Authentication mekanizması benzer bir yapıyı takip ettiği için, Spring Security, Pre-Authentication
sağlayıcılarını uygulamak için dahili bir framework sunan bir dizi sınıfa sahiptir. Bu, tekrarlanan kod yazımını önler
ve yeni uygulamaların baştan yazılmadan yapısal bir şekilde eklenebilmesini sağlar. Yani, Pre-Authentication
mekanizmalarının ortak işlemleri ve yapıları zaten bu dahili sınıflar tarafından sağlandığı için, yeni bir
Pre-Authentication mekanizması eklemek istediğinizde mevcut kodu yeniden yazmak zorunda kalmazsınız. Bunun yerine,
mevcut yapıları kullanarak yeni bir uygulama ekleyebilir ve gerektiğinde yapıyı özelleştirebilirsiniz.

Eğer X.509 kimlik doğrulama gibi bir şey kullanmak istiyorsanız, bu sınıfları bilmek zorunda değilsiniz. Çünkü Spring
Security, X.509 kimlik doğrulama gibi belirli Pre-Authentication mekanizmaları için basitleştirilmiş bir yapılandırma
seçeneği sağlar. Bu yapılandırma seçeneği, ilgili mekanizmanın gereksinimlerini karşılamak için gerekli olan sınıfları
otomatik olarak ayarlar ve kullanıma hazır hale getirir. Eğer açıkça tanımlanmış bir bean yapılandırması kullanmanız
gerekiyorsa veya kendi uygulamanızı yazmayı planlıyorsanız, sağlanan uygulamaların nasıl çalıştığını anlamak önemlidir.
Sınıfları **org.springframework.security.web.authentication.preauth** altında bulabilirsiniz.

### AbstractPreAuthenticatedProcessingFilter

Bu sınıf, Security Context'in mevcut içeriğini kontrol eder ve boş ise kullanıcı bilgilerini HTTP isteğinden çıkarmaya
çalışır ve bunları AuthenticationManager'a iletmeye çalışır. Alt sınıflar, bu bilgiyi elde etmek için aşağıdaki
methodları override ederler

```
protected abstract Object getPreAuthenticatedPrincipal(HttpServletRequest request);

protected abstract Object getPreAuthenticatedCredentials(HttpServletRequest request);
```

Bu işlemleri yaptıktan sonra, filtre dönen verileri içeren bir PreAuthenticatedAuthenticationToken oluşturur ve kimlik
doğrulama için sunar. Burada "kimlik doğrulama" ile aslında kullanıcının yetkilerini yüklemek gibi daha fazla işlem
yapmak kastedilir, ancak standart Spring Security kimlik doğrulama mimarisi takip edilir. Diğer Spring Security kimlik
doğrulama filtreleri gibi, Pre-Authentication filtresi de authenticationDetailsSource özelliğine sahiptir. Varsayılan
olarak, bu özellik, oturum kimliği ve kaynak IP adresi gibi ek bilgileri WebAuthenticationDetails nesnesinde saklamak
için kullanılır ve Authentication nesnesinin details özelliğine yerleştirilir. Eğer Pre-Authentication mekanizması
kullanıcı rol bilgilerini sağlayabiliyorsa, bu bilgiler de ayrıca details özelliğinde saklanır ve details
GrantedAuthoritiesContainer arabirimini uygular. Bu şekilde, kullanıcı rol bilgileri Authentication nesnesi içinde
erişilebilir hale gelir. Bu, kimlik doğrulama provider'ının kullanıcıya dışarıdan atanmış yetkilere erişmesini sağlar.
Bir sonraki adımda concrete bir örneğe bakacağız.

* J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource

Eğer filtre, authenticationDetailsSource olarak bu sınıfın bir örneğiyle yapılandırılmışsa, yetki bilgileri, önceden
belirlenmiş bir "mappable roles" kümesi için isUserInRole(String role) metodunun çağrılmasıyla elde edilir. Bu sınıf, bu
bilgileri yapılandırılmış bir MappableAttributesRetriever'dan alır. Mevcut olası implementasyonlar arasında, bir liste
üzerinde sabit bir şekilde kodlama yapmak ve rol bilgilerini bir web.xml dosyasındaki <security-role> bilgilerinden
okumak bulunur.Rol (veya attribute)lerin Spring Security GrantedAuthority nesnelerine eşlenmesi için yapılandırılmış bir
Attributes2GrantedAuthoritiesMapper kullanılan bir ek aşama bulunur. Varsayılan olarak, isimlere genellikle ROLE_ ön eki
eklenir, ancak davranış üzerinde tam kontrol sağlar.

### PreAuthenticatedAuthenticationProvider

Pre-Authentication provider'ının yapması gerekenler, kullanıcı için UserDetails nesnesini yüklemekten ibarettir. Bunun
için AuthenticationUserDetailsService'ye yetki devredilir. Bu, standart UserDetailsService'e benzer, ancak yalnızca
kullanıcı adı yerine bir Authentication nesnesi alır:

```
public interface AuthenticationUserDetailsService {
	UserDetails loadUserDetails(Authentication token) throws UsernameNotFoundException;
}
```

Bu arayüzün başka kullanımları da olabilir, ancak Pre-Authentication ile kullanıldığında, önceki bölümde gördüğümüz
gibi, Authentication nesnesinde paketlenmiş olan yetkilere erişim sağlar.
PreAuthenticatedGrantedAuthoritiesUserDetailsService sınıfı bunu yapar. Alternatif olarak,
UserDetailsByNameServiceWrapper uygulaması aracılığıyla standart bir UserDetailsService'e yetki devredebilir.

### Http403ForbiddenEntryPoint

AuthenticationEntryPoint, kimlik doğrulaması yapılmamış bir kullanıcı için (korumalı bir kaynağa erişmeye çalıştığında)
kimlik doğrulama sürecini başlatma sorumluluğunu üstlenir. Ancak, Pre-Authentication durumunda bu geçerli değildir. Eğer
başka kimlik doğrulama mekanizmalarıyla birlikte Pre-Authentication kullanmıyorsanız, ExceptionTranslationFilter'ı bu
sınıfın bir örneğiyle yapılandırırsınız. Bu durumda, kullanıcı AbstractPreAuthenticatedProcessingFilter tarafından
reddedildiğinde (kimlik doğrulaması null olarak döndüğünde) çağrılır. Her zaman 403-forbidden yanıt kodunu döndürür.

## Concrete Implementations

### Request-Header Authentication (Siteminder)

Bir harici kimlik doğrulama sistemi, belirli header'ları HTTP isteğine ekleyerek uygulamaya bilgi sağlayabilir. Bunun
iyi bilinen bir örneği Siteminder'dır, kullanıcı adını SM_USER adlı bir başlıkta iletiyor. Bu mekanizma, yalnızca
başlıktan kullanıcı adını çıkaran RequestHeaderAuthenticationFilter sınıfı tarafından desteklenir. Varsayılan olarak
başlık adı olarak SM_USER kullanır

Bu tür bir sistem kullanılırken, framework hiçbir kimlik doğrulama kontrolü yapmaz ve harici sistem doğru şekilde
yapılandırılmış ve uygulamaya erişim koruması sağlamaktadır. Bir saldırgan, bu tespit edilmeden orijinal isteğinde
header'larda sahtecilik yapabilirse, istediği herhangi bir kullanıcı adını seçebilir. Bu nedenle, harici sistem doğru
şekilde yapılandırılmalı ve güvenlik önlemleri alınmalıdır.

* Siteminder Example Configuration XML:

```
<security:http>
<!-- Additional http configuration omitted -->
<security:custom-filter position="PRE_AUTH_FILTER" ref="siteminderFilter" />
</security:http>

<bean id="siteminderFilter" class="org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter">
<property name="principalRequestHeader" value="SM_USER"/>
<property name="authenticationManager" ref="authenticationManager" />
</bean>

<bean id="preauthAuthProvider" class="org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider">
<property name="preAuthenticatedUserDetailsService">
	<bean id="userDetailsServiceWrapper"
		class="org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper">
	<property name="userDetailsService" ref="userDetailsService"/>
	</bean>
</property>
</bean>

<security:authentication-manager alias="authenticationManager">
<security:authentication-provider ref="preauthAuthProvider" />
</security:authentication-manager>
```

Burada, güvenlik ad alanının yapılandırma için kullanıldığı varsayılmıştır. Ayrıca, kullanıcının rollerini yüklemek için
yapılandırmanıza bir UserDetailsService ("userDetailsService" olarak adlandırılan) eklediğinizi varsayıyoruz.

### Java EE Container Authentication

2eePreAuthenticatedProcessingFilter sınıfı, HttpServletRequest'in userPrincipal özelliğinden kullanıcı adını çıkarır. Bu
filtre genellikle Java EE rolleriyle birlikte kullanılır ve daha önce
J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource bölümünde açıklandığı şekilde kullanılır.