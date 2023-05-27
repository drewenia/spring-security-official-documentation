# Handling Logouts

Varsayılan olarak, Spring Security bir /logout endpoint oluşturur, bu nedenle ek kod gerekmez

## Understanding Logout's Architecture

Spring Security, spring-boot-starter-security bağımlılığını dahil ettiğiniz veya @EnableWebSecurity anotasyonunu
kullandığınızda, session kapatma desteğini otomatik olarak ekler. Varsayılan olarak GET /logout ve POST /logout
isteklerine yanıt verir.

GET /logout isteği yapıldığında, Spring Security session kapatma onay sayfasını görüntüler. Kullanıcı için önemli bir
double-checking mekanizması sağlamanın yanı sıra,gereken CSRF token'ı POST /logout isteğine sağlamak için basit bir yol
sunar.

Uygulamanızda sessionu kapatmak için GET /logout kullanmanıza gerek yoktur. Talepte gerekli CSRF tokeni bulunduğu
sürece, uygulamanız sessionu kapatmaya neden olmak için basitçe POST /logout yapabilir.

Eğer POST /logout isteği yaparsanız, Spring Security varsayılan olarak LogoutHandler ile işlemleri tamamlar:

* HTTP session'i geçersiz kıl (SecurityContextLogoutHandler)
* SecurityContextHolderStrategy'yi temizleyin (SecurityContextLogoutHandler)
* SecurityContextRepository'yi temizleyin (SecurityContextLogoutHandler)
* Herhangi bir RememberMe kimlik doğrulamasını temizleyin (TokenRememberMeServices / PersistentTokenRememberMeServices)
* Kayıtlı herhangi bir CSRF tokenini (CsrfLogoutHandler) temizleyin
* Bir LogoutSuccessEvent (LogoutSuccessEventPublishingLogoutHandler) başlatın

Tamamlandığında, /login?logout'a yönlendiren varsayılan LogoutSuccessHandler'ı kullanacaktır.

## Customizing Logout URIs

LogoutFilter, "/logout" isteklerini yakalar ve sessionu geçersiz kılmak ve kimlik doğrulamayı temizlemek gibi gerekli
çıkış işlemlerini gerçekleştirir. AuthorizationFilter'dan önce yer aldığı için, "/logout" ucu erişime açıktır ve ayrıca
özel bir izin yapılandırması yapılmasına gerek yoktur. Bu nedenle, yalnızca kendi oluşturduğunuz custom logout
endpoints'e erişilebilir olması için genellikle bir permitAll yapılandırması gerekir. Örneğin, Spring Security'nin
eşleştirdiği URI'yi basitçe değiştirmek isterseniz, bunu DSL sessionunu kapatırken aşağıdaki şekilde yapabilirsiniz:

```
http
    .logout((logout) -> logout.logoutUrl("/my/logout/uri"))
```

ve yalnızca LogoutFilter'ı ayarladığı için hiçbir yetkilendirme değişikliği gerekmez.

Ancak, örneğin Spring MVC'yi kullanarak kendi logout success endpoint'inizi (veya nadiren kendi logout endpoint'inizi)
oluşturursanız, Spring Security'de buna izin vermeniz gerekir. Bunun nedeni, Spring MVC'nin talebinizi Spring Security'
den sonra işlemesidir.

Bunu, authorizeHttpRequests veya <intercept-url> kullanarak aşağıdaki gibi yapabilirsiniz:

```
http
    .authorizeHttpRequests((authorize) -> authorize
        .requestMatchers("/my/success/endpoint").permitAll()
        // ...
    )
    .logout((logout) -> logout.logoutSuccessUrl("/my/success/endpoint"))s
```

Bu örnekte, LogoutFilter'a işlemin tamamlandığında "/my/success/endpoint" sayfasına yönlendirme yapması söylenir ve
AuthorizationFilter'da "/my/success/endpoint" yoluna açık erişim izni verilir.

Spring Security konfigürasyonunda Java yapılandırması kullanılarak, logout işlemi için permitAll özelliğini kullanmanın
daha pratik bir yöntem olduğunu belirtilmelidir. Bu sayede, logout işlemi için ayrıca izin vermek için
AuthorizationFilter'a müdahale etmek yerine, logout DSL içindeki permitAll özelliği kullanılarak işlem tamamlanabilir.
Bu yaklaşım, kodun daha temiz ve anlaşılır olmasını sağlar.

```
http
    .authorizeHttpRequests((authorize) -> authorize
        // ...
    )
    .logout((logout) -> logout
        .logoutSuccessUrl("/my/success/endpoint")
        .permitAll()
    )
```

bu, tüm session kapatma URI'lerini sizin için izin listesine ekleyecektir.

## Adding Clean-up Actions

Java yapılandırması kullanıyorsanız, çıkış DSL'sinde addLogoutHandler yöntemini çağırarak kendi temizleme eylemlerinizi
ekleyebilirsiniz, örneğin:

```
CookieClearingLogoutHandler cookies = new CookieClearingLogoutHandler("our-custom-cookie");
http
    .logout((logout) -> logout.addLogoutHandler(cookies))
```

LogoutHandlers temizleme amaçlı olduğundan, exception fırlatmamalıdır. LogoutHandler functional bir interface
olduğundan, lambda olarak kullanılabilir

Bazı logout işlemi yapılandırmaları yaygın olduğu için, bunlar doğrudan logout DSL ve <logout> öğesinde kullanıma
sunulmuştur. Örneğin, session geçersiz kılma yapılandırması ve silinmesi gereken ek cookies'lerin belirlenmesi gibi
işlemler bu kategoriye örnek verilebilir. CookieClearingLogoutHandler'ı yukarıda görüldüğü gibi yapılandırabilirsiniz.

Veya bunun yerine uygun yapılandırma değerini şu şekilde ayarlayabilirsiniz:

```
http
    .logout((logout) -> logout.deleteCookies("our-custom-cookie"))
```

Note:SecurityContextLogoutHandler sessionu geçersiz kılarak onu kaldırdığı için JSESSIONID tanımlama bilgisinin gerekli
olmadığını belirtmek.

### Using Clear-Site-Data to Log Out the User

The Clear-Site-Data HTTP header'i, tarayıcıların, ait oldukları web sitesine ait cookiesleri, depolama alanını ve
önbelleği temizlemek için bir talimat olarak desteklediği bir başlıktır. Bu, session cookiesi de dahil olmak üzere her
şeyin logout işlemi sırasında temizlendiğinden emin olmanın kullanışlı ve güvenli bir yoludur.

Clear-Site-Data başlığını çıkışta şu şekilde yazmak için Spring Security'yi yapılandırmayı ekleyebilirsiniz:

```
HeaderWriterLogoutHandler clearSiteData = new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter());
http
    .logout((logout) -> logout.addLogoutHandler(clearSiteData))
```

ClearSiteDataHeaderWriter constructor'ına , temizlenmesini istediğiniz şeylerin listesini verirsiniz.

Yukarıdaki yapılandırma,tüm site verilerini temizler, ancak bunu yalnızca şu şekilde cookies'leri kaldıracak şekilde de
yapılandırabilirsiniz:

```
HeaderWriterLogoutHandler clearSiteData = new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(Directives.COOKIES));
http
    .logout((logout) -> logout.addLogoutHandler(clearSiteData))
```

## Customizing Logout Success

logoutSuccessUrl çoğu durumda yeterli olsa da, logout işlemi tamamlandığında farklı bir işlem yapmanız gerekebilir.
LogoutSuccessHandler, logout işlemi başarıyla tamamlandığında özelleştirilmiş işlemler yapmak için kullanılan Spring
Security bileşenidir.

Örneğin, yönlendirme yerine yalnızca bir durum kodu döndürmek isteyebilirsiniz. Bu durumda, aşağıdaki gibi bir başarı
işleyici örneği sağlayabilirsiniz:

```
http
    .logout((logout) -> logout.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()))
```

LogoutSuccessHandler işlevsel bir arayüz olduğundan, lambda kullanabilirsiniz.

## Creating a Custom Logout Endpoint

Logout işlemini yapılandırmak için sağlanan logout DSL'in kullanılması kesinlikle önerilir. Bunun bir nedeni, gerekli
olan Spring Security bileşenlerini çağırmayı unutmak ve uygun ve tam bir çıkış işlemi sağlamamaktır.

Aslında, özel bir LogoutHandler'ı kaydetmek, oturumu kapatmak için bir Spring MVC endpoint'i oluşturmaktan genellikle
daha kolaydır.

Bununla birlikte, kendinizi aşağıdaki gibi özel bir logout endpoint'e gerekli olduğu bir durumda bulursanız:

```
@PostMapping("/my/logout")
public String performLogout() {
    // .. perform logout
    return "redirect:/home";
}
```

o zaman, güvenli ve eksiksiz bir logout sağlamak için bu endpoint'in Spring Security'nin SecurityContextLogoutHandler'ı
çağırmasını sağlamanız gerekir. En azından aşağıdaki gibi bir şeye ihtiyaç vardır:

```
SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();

@PostMapping("/my/logout")
public String performLogout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
    // .. perform logout
    this.logoutHandler.doLogout(request, response, authentication);
    return "redirect:/home";
}
```

Yukarıda ki kod, gerektiğinde SecurityContextHolderStrategy ve SecurityContextRepository'yi temizleyecektir. Ayrıca,
endpoint'e açıkça permit vermeniz gerekir

Uyarı : SecurityContextLogoutHandler'ın çağrılamaması, SecurityContext'in sonraki isteklerde hala mevcut olabileceği
anlamına gelir, yani kullanıcının oturumu gerçekten kapatılmamış demektir.
