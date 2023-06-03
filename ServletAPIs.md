# Servlet API Integration

## Servlet 2.5+ Integration

Bu bölüm, Spring Security'nin Servlet 2.5 spesifikasyonuyla nasıl entegre olduğunu açıklar.

### HttpServletRequest.getRemoteUser()

HttpServletRequest.getRemoteUser(), veya kısaca request.getRemoteUser(), mevcut kimlik doğrulama yapılan kullanıcının
kullanıcı adını döndürür. Bu, SecurityContextHolder veya Authentication nesnesine doğrudan erişmeden kullanıcı adını
almanın pratik bir yoludur. getRemoteUser() tarafından döndürülen değerin null olup olmadığını kontrol ederek bir
kullanıcının kimlik doğrulamasını yapılıp yapılmadığını veya anonim olup olmadığını belirleyebilirsiniz.

Bu, uygulamanızda mevcut kullanıcı adını görüntülemek isterseniz faydalı olabilir.Kullanıcının kimlik
doğrulamasının yapıldığı veya yapılmadığı bilgisine sahip olmak, belirli kullanıcı arayüzü öğelerinin gösterilip
gösterilmeyeceğini belirlemek için faydalı olabilir (örneğin, kullanıcı kimlik doğrulaması yapıldığında görüntülenmesi
gereken logout bağlantısı gibi).

### HttpServletRequest.getUserPrincipal()

HttpServletRequest.getUserPrincipal(), SecurityContextHolder.getContext().getAuthentication() sonucunu döndürür. Bu,
genellikle kullanıcı adı ve parola tabanlı kimlik doğrulama kullanıldığında bir UsernamePasswordAuthenticationToken
örneği olan bir Authentication'dır. Bu, kullanıcınız hakkında ek bilgilere ihtiyacınız olduğunda faydalı olabilir.
Örneğin, özel bir UserDetailsService oluşturmuş olabilir ve kullanıcınız için bir ad ve soyad içeren özel bir
UserDetails döndürebilirsiniz. Bu bilgilere aşağıdaki gibi erişebilirsiniz.

```
Authentication auth = httpServletRequest.getUserPrincipal();
// assume integrated custom UserDetails called MyCustomUserDetails
// by default, typically instance of UserDetails
MyCustomUserDetails userDetails = (MyCustomUserDetails) auth.getPrincipal();
String firstName = userDetails.getFirstName();
String lastName = userDetails.getLastName();
```

Note : Dikkate değer bir nokta, bu kadar çok mantığı uygulamanın genellikle kötü bir uygulama olduğudur. Bunun yerine,
Spring Security ve Servlet API'sinin bağlantısını azaltmak için bunu merkezi bir hale getirmek daha iyi bir yaklaşımdır.

### HttpServletRequest.isUserInRole(String)

HttpServletRequest.isUserInRole(String), SecurityContextHolder.getContext().getAuthentication().getAuthorities() içinde,
isUserInRole(String) methoduna geçirilen rolle eşleşen bir GrantedAuthority bulunup bulunmadığını belirler. Genellikle
kullanıcılar bu yönteme ROLE_ prefix'ini vermeye gerek duymazlar, çünkü otomatik olarak eklenir. Örneğin, mevcut
kullanıcının "ROLE_ADMIN" yetkisine sahip olup olmadığını belirlemek istiyorsanız, aşağıdakini kullanabilirsiniz:

```
boolean isAdmin = httpServletRequest.isUserInRole("ADMIN");
```

Bu, belirli UI bileşenlerinin görüntülenip görüntülenmemesi gerektiğini belirlemek için kullanışlı olabilir. Örneğin,
yalnızca mevcut kullanıcı bir yönetici ise yönetici bağlantılarını görüntüleyebilirsiniz.

## Servlet 3+ Integration

Aşağıdaki bölümde, Spring Security'nin entegre olduğu Servlet 3 methodları açıklanmaktadır.

### HttpServletRequest.authenticate(HttpServletRequest,HttpServletResponse)

HttpServletRequest.authenticate(HttpServletRequest, HttpServletResponse) methodunu kullanarak bir kullanıcının kimlik
doğrulamasını sağlayabilirsiniz. Eğer kimlik doğrulanmamışlarsa, yapılandırılmış AuthenticationEntryPoint kullanıcıya
kimlik doğrulamasını talep etmek için kullanılır (giriş sayfasına yönlendirilir).

### HttpServletRequest.login(String,String)

HttpServletRequest.login(String, String) methodunu kullanarak mevcut AuthenticationManager ile kullanıcının kimlik
doğrulamasını yapabilirsiniz. Örneğin, aşağıdaki kod parçası kullanıcı adı olarak "user" ve şifre olarak "password" ile
kimlik doğrulaması yapmaya çalışır:

```
try {
httpServletRequest.login("user","password");
} catch(ServletException ex) {
// fail to authenticate
}
```

Note : Eğer Spring Security'nin başarısız kimlik doğrulama girişimini işlemesini istiyorsanız, ServletException'i
yakalamak zorunda değilsiniz. Spring Security, AuthenticationException'ı işleyecek ve yapılandırılmış olan
AuthenticationFailureHandler'ı kullanarak işlemi gerçekleştirecektir.

### HttpServletRequest.logout()

HttpServletRequest.logout() yöntemini kullanarak mevcut kullanıcıyı oturumu kapatabilirsiniz. Bu yöntem, mevcut
kullanıcının oturumunu sonlandırır ve security context'i temizler.

Genellikle bu, SecurityContextHolder'ın temizlendiği, HttpSession'ın geçersiz kılındığı, "Remember Me" kimlik
doğrulamasının temizlendiği vb. anlamına gelir. Bununla birlikte, yapılandırılmış LogoutHandler uygulamaları Spring
Security yapılandırmanıza bağlı olarak değişir. HttpServletRequest.logout() çağrıldıktan sonra hala bir response'u yazma
sorumluluğu size aittir. Genellikle bu, bir hoş geldiniz sayfasına yönlendirme içerir.

### AsyncContext.start(Runnable)

AsyncContext.start(Runnable) methodu, kimlik bilgilerinizin yeni Thread'e aktarıldığından emin olur. Spring Security'nin
asynchronous desteğini kullanarak, Spring Security AsyncContext.start(Runnable) methodunu geçersiz kılar ve Runnable
işlenirken mevcut SecurityContext'in kullanılmasını sağlar. Aşağıdaki örnek, mevcut kullanıcının kimlik doğrulamasını
çıktılar:

```
final AsyncContext async = httpServletRequest.startAsync();
async.start(new Runnable() {
	public void run() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		try {
			final HttpServletResponse asyncResponse = (HttpServletResponse) async.getResponse();
			asyncResponse.setStatus(HttpServletResponse.SC_OK);
			asyncResponse.getWriter().write(String.valueOf(authentication));
			async.complete();
		} catch(Exception ex) {
			throw new RuntimeException(ex);
		}
	}
});
```

### Async Servlet Support

Eğer Java tabanlı bir yapılandırma kullanıyorsanız, kullanıma hazırsınız demektir. Eğer XML tabanlı bir yapılandırma
kullanıyorsanız, birkaç güncelleme yapmanız gerekmektedir. İlk adım, web.xml dosyanızın en az 3.0 şemasını kullanacak
şekilde güncellendiğinden emin olmaktır. (XML)

```
<web-app xmlns="http://java.sun.com/xml/ns/javaee"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="http://java.sun.com/xml/ns/javaee https://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"
version="3.0">

</web-app>
```

Sonraki adım, springSecurityFilterChain'in asenkron istekleri işlemek için yapılandırıldığından emin olmanız
gerekmektedir. (XML)

```
<filter>
<filter-name>springSecurityFilterChain</filter-name>
<filter-class>
	org.springframework.web.filter.DelegatingFilterProxy
</filter-class>
<async-supported>true</async-supported>
</filter>
<filter-mapping>
<filter-name>springSecurityFilterChain</filter-name>
<url-pattern>/*</url-pattern>
<dispatcher>REQUEST</dispatcher>
<dispatcher>ASYNC</dispatcher>
</filter-mapping>
```

Artık Spring Security, güvenlik bağlamınızın asenkron isteklere de yayıldığından emin olur.

Spring Security 3.2 ve öncesinde, SecurityContextHolder'dan alınan SecurityContext otomatik olarak HttpServletResponse
gönderildiği anda kaydedilirdi. Bu durum asenkron bir ortamda sorunlara yol açabilir. Aşağıdaki örneği düşünelim:

```
httpServletRequest.startAsync();
new Thread("AsyncThread") {
	@Override
	public void run() {
		try {
			// Do work
			TimeUnit.SECONDS.sleep(1);

			// Write to and commit the httpServletResponse
			httpServletResponse.getOutputStream().flush();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
}.start();
```

Sorun, bu Thread'in Spring Security tarafından tanınmaması ve dolayısıyla SecurityContext'in buna iletilmemesidir. Bu,
HttpServletResponse'i gönderirken SecurityContext'in olmadığı anlamına gelir. Spring Security, HttpServletResponse'i
gönderirken otomatik olarak SecurityContext'i kaydettiğinde, oturum açmış bir kullanıcı kaybolurdu.

Spring Security 3.2'den itibaren, HttpServletRequest.startAsync() çağrıldığında, Spring Security artık
HttpServletResponse'in gönderilmesiyle SecurityContext'i otomatik olarak kaydetmeyi bırakmaktadır.

## Servlet 3.1+ Integration

Aşağıdaki bölümde, Spring Security'nin entegre olduğu Servlet 3.1 yöntemleri açıklanmaktadır.

### HttpServletRequest#changeSessionId()

HttpServletRequest.changeSessionId() Servlet 3.1 ve daha üstü sürümlerde Session Fixation saldırılarına karşı koruma
sağlayan varsayılan bir yöntemdir.