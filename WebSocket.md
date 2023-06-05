# WebSocket Security

Spring Security 4, Spring WebSocket desteğini güvence altına almak için destek ekledi. Bu bölüm, Spring Security'nin
WebSocket desteğini nasıl kullanacağınızı açıklar.

- Direct JSR-356 Support

Spring Security, doğrudan JSR-356 desteği sağlamaz çünkü bunu yapmak çok az değer sağlar. Bunun nedeni, biçimin
bilinmemesi ve Spring'in bilinmeyen bir biçimi güvence altına almak için yapabileceği çok az şey olmasıdır.Ek olarak,
JSR-356, intercept message'lar için bir yol sağlamaz, bu nedenle güvenlik istilası olacaktır.

## WebSocket Authentication

WebSockets, WebSocket bağlantısı yapıldığında HTTP request'inde bulunan authentication bilgisini kullanır. Bu,
HttpServletRequest üzerindeki Principal'in WebSockets'a devredileceği anlamına gelir. Eğer Spring Security
kullanıyorsanız, HttpServletRequest üzerindeki Principal otomatik olarak üzerine yazılır.

Daha somut bir şekilde ifade etmek gerekirse, WebSocket uygulamanızda bir kullanıcının kimlik doğrulama yaptığından emin
olmak için yapmanız gereken tek şey, Spring Security'yi HTTP tabanlı web uygulamanızı kimlik doğrulamak için
yapılandırmaktır.

## WebSocket Authorization

Spring Security 4.0, Spring Messaging abstraction'i aracılığıyla WebSockets için yetkilendirme desteği eklemiştir.

Spring Security 5.8 sürümünde, bu destek AuthorizationManager API'sini kullanacak şekilde güncellenmiştir.

Java Configuration kullanarak yetkilendirmeyi yapılandırmak için, @EnableWebSocketSecurity annotasyonunu eklemeniz ve
AuthorizationManager<Message<?>> tipinde bir bean'i yayınlamanız (veya XML kullanarak use-authorization-manager
attribute'unu kullanmanız) yeterlidir. Bunun için AuthorizationManagerMessageMatcherRegistry kullanarak endpoint
pattern'lerini belirtebilirsiniz:

```
@Configuration
@EnableWebSocketSecurity (1) (2)
public class WebSocketSecurityConfig {

    @Bean
    AuthorizationManager<Message<?>> messageAuthorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
        messages
                .simpDestMatchers("/user/**").hasRole("USER")

        return messages.build();
    }
}
```

1 - Same Origin Policy'i uygulamak için, gelen herhangi bir CONNECT mesajı geçerli bir CSRF tokeni gerektirir.

2 - SecurityContextHolder, herhangi bir gelen request için simpUser header attribute'u içinde kullanıcıyla doldurulur.

3 - Messages doğru authorization gerektirir. Özellikle, /user/ ile başlayan herhangi bir gelen message, ROLE_USER
yetkisini gerektirecektir.

### Custom Authorization

AuthorizationManager kullanırken customize oldukça basittir. Örneğin, aşağıdaki gibi AuthorityAuthorizationManager
kullanarak tüm messages'ların "USER" rolüne sahip olmasını gerektiren bir AuthorizationManager yayınlayabilirsiniz:

```
@Configuration
@EnableWebSocketSecurity
public class WebSocketSecurityConfig {

    @Bean
    AuthorizationManager<Message<?>> messageAuthorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
        return AuthorityAuthorizationManager.hasRole("USER");
    }
}
```

Mesajları daha ileri düzeyde eşleştirmenin çeşitli yolları vardır, aşağıdaki daha gelişmiş bir örnekte görülebilir:

```
@Configuration
public class WebSocketSecurityConfig {

    @Bean
    public AuthorizationManager<Message<?>> messageAuthorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
        messages
                .nullDestMatcher().authenticated() (1)
                .simpSubscribeDestMatchers("/user/queue/errors").permitAll() (2)
                .simpDestMatchers("/app/**").hasRole("USER") (3)
                .simpSubscribeDestMatchers("/user/**", "/topic/friends/*").hasRole("USER") (4)
                .simpTypeMatchers(MESSAGE, SUBSCRIBE).denyAll() (5)
                .anyMessage().denyAll(); (6)

        return messages.build();
    }
}
```

1 - Hedefi olmayan (yani MESSAGE veya SUBSCRIBE türünde olmayan) herhangi bir mesajın, kullanıcının kimlik doğrulamasını
gerektireceği belirtilir.

2 - /user/queue/errors'a herkes subscribe olabilir

3 - "/app/" ile başlayan bir hedefi olan tüm iletiler, kullanıcının ROLE_USER rolüne sahip olmasını gerektirecektir.

4 - "/user/" veya "/topic/friends/" ile başlayan ve SUBSCRIBE türünde olan herhangi bir ileti, ROLE_USER gerektirir

5 - Diğer MESSAGE veya SUBSCRIBE türünde olan tüm diğer message'lar reddedilir. 6. adım sayesinde bu adıma ihtiyacımız
olmasa da, belirli mesaj türlerine göre eşleştirme yapmanın nasıl yapılabileceğini göstermektedir.

6 - Diğer tüm Mesajlar reddedilir. Bu, hiçbir mesajı kaçırmadığınızdan emin olmak için iyi bir fikirdir.

### WebSocket Authorization Notes

Uygulamanızı düzgün bir şekilde güvence altına almak için Spring'in WebSocket desteğini anlamanız gerekir.

- WebSocket Authorization on Message Types

SUBSCRIBE ve MESSAGE türündeki mesajların farkını anlamanız ve Spring içinde nasıl çalıştıklarını anlamanız
gerekmektedir.

Bir sohbet uygulaması düşünün:

Sistem, /topic/system/notifications hedefine yönlendirilen bir bildirim MESSAGE'ıyla tüm kullanıcılara bildirim
gönderebilir.

Client, /topic/system/notifications'a SUBSCRIBE olarak bildirim alabilirler.

Clients /topic/system/notifications hedefine SUBSCRIBE olmalarına izin vermek istiyoruz, ancak bu hedefe bir MESSAGE
göndermelerine izin vermek istemiyoruz. Eğer /topic/system/notifications hedefine bir MESSAGE göndermelerine izin
verseydik, kullanıcılar doğrudan bu endpoint'e bir mesaj gönderebilir ve sistemi taklit edebilirlerdi.

Genel olarak, uygulamalar için broker prefix ile başlayan (/topic/ veya /queue/) bir hedefe gönderilen herhangi bir
MESSAGE'ın reddedilmesi yaygındır.

- WebSocket Authorization on Destinations

Ayrıca destination'ların nasıl dönüştürüldüğünü de anlamanız gerekmektedir.

Bir sohbet uygulaması düşünün:

Kullanıcılar, /app/chat hedefine bir mesaj göndererek belirli bir kullanıcıya mesaj gönderebilir.

Uygulama, mesajı alır ve from attribute'unun mevcut kullanıcı olarak belirtildiğinden emin olur (client'a güvenemeyiz).

Daha sonra uygulama, SimpMessageSendingOperations.convertAndSendToUser("toUser", "/queue/messages", message) kullanarak
mesajı alıcıya gönderir.

Message, /queue/user/messages-<sessionid> hedefine dönüştürülür.

Bu sohbet uygulamasında client'a /user/queue dinlemesine izin vermek istiyoruz, bu da /queue/user/messages-<sessionid>
olarak dönüştürülür. Bununla birlikte, client'in /queue/* dinlemesine izin vermek istemiyoruz, çünkü bu, istemcinin her
kullanıcının mesajlarını görmesine izin verir.

Genel olarak, uygulamalar için /topic/ veya /queue/ ile başlayan bir message'in herhangi bir SUBSCRIBE işlemini
reddetmek yaygındır. Özel durumlar için istisnalar yapabiliriz

### Outbound Messages

Spring Framework referans belgelerinde "Flow of Messages" başlıklı bir bölüm bulunmaktadır ve bu bölümde mesajların
sistemin içinden nasıl aktığı açıklanmaktadır. Dikkat edilmesi gereken nokta, Spring Security'nin yalnızca
clientInboundChannel'ı güvence altına almasıdır. Spring Security, clientOutboundChannel'ı güvence altına almaya
çalışmaz.

Bu durumun en önemli nedeni performanstır. Gelen her bir mesaj için genellikle daha fazla mesaj gönderilir. Outbound
message'ları güvence altına almak yerine, endpoint'lere olan subscription'ları güvence altına almaya teşvik ederiz.
Böylece gelen mesajların işlenme performansı artar ve gereksiz yükten kaçınılmış olur.

## Enforcing Same Origin Policy

Dikkat edilmesi gereken önemli bir nokta, tarayıcının WebSocket bağlantıları için Same Origin Policy
uygulamamasıdır. Bu oldukça önemli bir husustur. Same Origin Policy, tarayıcının farklı kökenden gelen kaynaklara
erişimi kısıtlar, ancak WebSocket bağlantıları için bu kısıtlama mevcut değildir. Bu durum, güvenlik açısından dikkate
alınması gereken bir noktadır ve uygulama tarafında gerekli önlemlerin alınması önemlidir.

### Why Same Origin

Aşağıdaki senaryoyu düşünelim: Bir kullanıcı bank.com'a girer ve hesabına kimlik doğrulaması yapar. Aynı kullanıcı
tarayıcısında başka bir sekme açar ve evil.com'a girer. Same Origin Policy, evil.com'un bank.com'dan veri okumasını
veya bank.com'a veri yazmasını engeller.

WebSockets iletişimi Same Origin Policy kapsamında gerçekleşmez. Geleneksel HTTP request'lerini aksine, WebSockets
client ve sunucu arasında iki yönlü iletişim sağlar ve köken (origin) bağımsız olarak çalışır. Bu da, bank.com'un açıkça
engellemediği sürece evil.com'un kullanıcı adına WebSocket verilerine erişebileceği ve manipüle edebileceği anlamına
gelir.

SockJS WebSockets'i taklit etmeye çalışırken Same Origin Policy'i de atlar. Bu nedenle, SockJS kullanan
geliştiricilerin uygulamalarını harici current domain'den açıkça koruması gerekmektedir.

### Spring WebSocket Allowed Origin

Spring 4.1.5 ve sonraki sürümleriyle birlikte, Spring'in WebSocket ve SockJS desteği mevcuttur ve erişimi mevcut domain'
e kısıtlar. Spring Security, daha fazla güvenlik sağlamak için bu konuda ek bir koruma katmanı ekler.

### Adding CSRF to Stomp Headers

Spring Security varsayılan olarak herhangi bir CONNECT message türünde CSRF token gerektirir. Bu, yalnızca CSRF token'e
erişimi olan bir site'nin bağlantı kurabileceğini sağlar. CSRF token'e yalnızca same origin erişebildiği için external
domain'ler bağlantı kuramaz.

Genellikle CSRF token'ı bir HTTP header'i veya HTTP parametresi olarak eklememiz gerekiyor. Ancak, SockJS bu seçeneklere
izin vermez. Bunun yerine, CSRF token'ını Stomp header'larına eklememiz gerekmektedir. (JavaScript)

```
var headerName = "${_csrf.headerName}";
var token = "${_csrf.token}";
```

Statik HTML kullanıyorsanız, CsrfToken'ı bir REST endpoint'inde kullanıma sunabilirsiniz. Örneğin, aşağıdaki, /csrf
URL'sinde CsrfToken'ı ortaya çıkarır:

```
@RestController
public class CsrfController {

    @RequestMapping("/csrf")
    public CsrfToken csrf(CsrfToken token) {
        return token;
    }
}
```

JavaScript, endpoint'e bir REST çağrısı yapabilir ve response'u headerName ile token'i doldurmak için kullanabilir.

Artık tokeni Stomp client'ina dahil edebiliriz: (JavaScript)

```
...
var headers = {};
headers[headerName] = token;
stompClient.connect(headers, function(frame) {
  ...

})
```

### Disable CSRF within WebSockets

Bu noktada, @EnableWebSocketSecurity kullanılırken CSRF yapılandırılamaz, ancak bu muhtemelen gelecekteki bir sürümde
eklenecektir.

CSRF'yi devre dışı bırakmak için @EnableWebSocketSecurity kullanmak yerine XML desteğini kullanabilir veya Spring
Security component'lerini kendiniz ekleyebilirsiniz, örneğin:

```
@Configuration
public class WebSocketSecurityConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(new AuthenticationPrincipalArgumentResolver());
    }

    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        AuthorizationManager<Message<?>> myAuthorizationRules = AuthenticatedAuthorizationManager.authenticated();
        AuthorizationChannelInterceptor authz = new AuthorizationChannelInterceptor(myAuthorizationRules);
        AuthorizationEventPublisher publisher = new SpringAuthorizationEventPublisher(this.context);
        authz.setAuthorizationEventPublisher(publisher);
        registration.interceptors(new SecurityContextChannelInterceptor(), authz);
    }
}
```

Öte yandan, legacy-websocket-configuration kullanıyorsanız ve diğer domain'lerin sitenize erişmesine izin vermek
istiyorsanız, Spring Security'nin korumasını devre dışı bırakabilirsiniz. Örneğin, Java Yapılandırmasında aşağıdakini
kullanabilirsiniz

```
@Configuration
public class WebSocketSecurityConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

    ...

    @Override
    protected boolean sameOriginDisabled() {
        return true;
    }
}
```

### Custom Expression Handler

Bazen, intercept-message XML elemanlarında tanımlanan access expression'ların nasıl işleneceğini özelleştirmek değerli
olabilir. Bunun için SecurityExpressionHandler<MessageAuthorizationContext<?>> türünde bir sınıf oluşturabilir ve XML
tanımınızda aşağıdaki gibi buna başvurabilirsiniz (XML) :

```
<websocket-message-broker use-authorization-manager="true">
    <expression-handler ref="myRef"/>
    ...
</websocket-message-broker>

<b:bean ref="myRef" class="org.springframework.security.messaging.access.expression.MessageAuthorizationContextSecurityExpressionHandler"/>
```

Eğer websocket-message-broker'ın eski bir kullanımından geçiş yapıyorsanız ve SecurityExpressionHandler<Message<?>>
arayüzünü uyguluyorsanız, aşağıdaki adımları izleyebilirsiniz:

1 - createEvaluationContext(Supplier, Message) methodunu ek olarak uygulayın

2 - O değeri MessageAuthorizationContextSecurityExpressionHandler ile wrap edin. İşte örnek bir kod parçası: (XML)

```
<websocket-message-broker use-authorization-manager="true">
    <expression-handler ref="myRef"/>
    ...
</websocket-message-broker>

<b:bean ref="myRef" class="org.springframework.security.messaging.access.expression.MessageAuthorizationContextSecurityExpressionHandler">
    <b:constructor-arg>
        <b:bean class="org.example.MyLegacyExpressionHandler"/>
    </b:constructor-arg>
</b:bean>
```

## Working with SockJS

SockJS, eski tarayıcıları desteklemek için yedek iletişim kanalları sağlar. Fallback seçeneklerini kullanırken,
SockJS'in Spring Security ile çalışabilmesi için bazı güvenlik kısıtlamalarını gevşetmemiz gerekmektedir.

### SockJs & frame-options

SockJS, iframe kullanarak çalışan bir iletişim taşıyıcısı kullanabilir. Spring Security'nin varsayılan olarak
clickjacking saldırılarını önlemek için siteyi çerçevelemeyi reddetmesi nedeniyle SockJS'in iframe tabanlı
taşıyıcılarının çalışabilmesi için Spring Security'nin yapılandırılması gerekmektedir

X-Frame-Options özelleştirilebilir ve frame-options öğesi ile yapılandırılabilir. Aşağıdaki örnek, Spring Security'e
X-Frame-Options: SAMEORIGIN kullanmasını söyleyerek aynı etki alanı içindeki iframe'lere izin verir: (XML)

```
<http>
    <!-- ... -->

    <headers>
        <frame-options
          policy="SAMEORIGIN" />
    </headers>
</http>
```

Benzer şekilde, aşağıdakileri kullanarak frame seçeneklerini Java Yapılandırması içinde same origin kullanacak şekilde
özelleştirebilirsiniz:

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

### SockJS & Relaxing CSRF

SockJS, herhangi bir HTTP tabanlı iletişim için CONNECT mesajlarında bir POST kullanır. Genellikle CSRF token'ını bir
HTTP header'i veya parametre olarak eklememiz gerekir. Ancak, SockJS bu seçeneklere izin vermez. Bunun yerine, CSRF
token'ını Stomp header'larında eklememiz gerekmektedir. Bu durumu açıklamak için "Adding CSRF to Stomp Headers"
başlıklı bölümdeki adımları izleyebilirsiniz.

SockJS kullanımında, özellikle connect URL'leri için CSRF korumasını gevşetmemiz gerekebilir. Ancak, her URL için CSRF
korumasını devre dışı bırakmak istemeyiz. Aksi takdirde, sitemiz CSRF saldırılarına açık hale gelir.

Bu işlemi Java yapılandırmanızda bir CSRF RequestMatcher sağlayarak kolayca gerçekleştirebilirsiniz. Böylece belirli
URL'ler veya URL pattern'leri için CSRF korumasını seçici olarak devre dışı bırakabilirsiniz. Örneğin, stomp
endpoint'imiz /chat ise, aşağıdaki yapılandırmayı kullanarak yalnızca /chat/ ile başlayan URL'ler için CSRF korumasını
devre dışı bırakabiliriz:

```
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                // ignore our stomp endpoints since they are protected using Stomp headers
                .ignoringRequestMatchers("/chat/**")
            )
            .headers(headers -> headers
                // allow same origin to frame our site to support iframe SockJS
                .frameOptions(frameOptions -> frameOptions
                    .sameOrigin()
                )
            )
            .authorizeHttpRequests(authorize -> authorize
                ...
            )
            ...
    }
}
```

XML tabanlı yapılandırma kullanıyorsak, thecsrf@request-matcher-ref kullanabiliriz. (XML) :

```
<http ...>
    <csrf request-matcher-ref="csrfMatcher"/>

    <headers>
        <frame-options policy="SAMEORIGIN"/>
    </headers>

    ...
</http>

<b:bean id="csrfMatcher"
    class="AndRequestMatcher">
    <b:constructor-arg value="#{T(org.springframework.security.web.csrf.CsrfFilter).DEFAULT_CSRF_MATCHER}"/>
    <b:constructor-arg>
        <b:bean class="org.springframework.security.web.util.matcher.NegatedRequestMatcher">
          <b:bean class="org.springframework.security.web.util.matcher.AntPathRequestMatcher">
            <b:constructor-arg value="/chat/**"/>
          </b:bean>
        </b:bean>
    </b:constructor-arg>
</b:bean>
```

## Legacy WebSocket Configuration

Spring Security 5.8'den önce Java yapılandırmasıyla mesaj yetkilendirmesini yapılandırmanın yolu,
AbstractSecurityWebSocketMessageBrokerConfigurer'i extend etmek ve MessageSecurityMetadataSourceRegistry'yi
yapılandırmaktı. Örnek olarak şöyle yapılabilirdi:

```
@Configuration
public class WebSocketSecurityConfig
      extends AbstractSecurityWebSocketMessageBrokerConfigurer { (1) (2)

    protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
        messages
                .simpDestMatchers("/user/**").authenticated() (3)
    }
}
```

1 - Herhangi bir gelen CONNECT mesajı, Same Origin Policy'i uygulamak için geçerli bir CSRF tokeni gerektirir.

2 - SecurityContextHolder, herhangi bir gelen request için simpUser header attribute'u içindeki kullanıcıyla doldurulur.
Bu mekanizma, Spring Security tarafından sağlanan bir component'dir ve kullanıcının kimliğini ve yetkilendirmesini
kolayca erişilebilir kılar.

3 - Mesajlarımızın uygun yetkilendirme gerektirdiğini belirtelim. Özellikle "/user/" ile başlayan gelen her mesajın
ROLE_USER yetkisine ihtiyaç duyacağını belirtelim.

Eski yapılandırmanın kullanılması, AbstractSecurityExpressionHandler'dan türetilmiş ve createEvaluationContextInternal
veya createSecurityExpressionRoot'u geçersiz kılan özel bir SecurityExpressionHandler'a sahipseniz faydalı olabilir.
Yeni AuthorizationManager API'si, ifadeleri değerlendirirken bunları çağırmaz, böylece Yetkilendirme aramasını erteler.

XML kullanıyorsanız, use-authorization-manager öğesini kullanmayarak veya false olarak ayarlayarak eski API'leri
kullanabilirsiniz.