# Http Firewall

Tanımladığınız patternlere karşı test yaparken mekanizmanın ne olduğunu ve hangi URL değerinin kullanıldığını anlamak
önemlidir.

ServletRequest için Servlet spesifikasyonu, getter metodları aracılığıyla erişilebilen ve eşleştirmek isteyebileceğimiz
birkaç özellik tanımlar. Bunlar, contextPath, servletPath, pathInfo ve queryString'dir. Spring Security, yalnızca
uygulama içindeki path'leri güvence altına almayı amaçlar, bu nedenle contextPath yok sayılır. Maalesef, servlet
spesifikasyonu belirli bir istek URI için servletPath ve pathInfo değerlerinin tam olarak ne içerdiğini
tanımlamaz.Örneğin, bir URL'nin her path segmenti, RFC 2396'da tanımlandığı gibi parametreler içerebilir (Bir tarayıcı
çerezleri desteklemediğinde ve jsessionid parametresi noktalı virgülden sonra URL'ye eklenmiş olarak görülebilir. Ancak,
RFC, bu parametrelerin URL'nin herhangi bir path segmentinde bulunmasına izin verir.) Spesifikasyon, bu parametrelerin
servletPath ve pathInfo değerlerine dahil edilip edilmemesi konusunda net bir şekilde belirtmez ve davranış, farklı
servlet konteynerları arasında değişir.Bir uygulama, path parametrelerini bu değerlerden çıkarmayan bir konteynere
dağıtıldığında, bir saldırgan istenen URL'ye bunları ekleyerek pattern eşleşmesinin beklenmedik şekilde başarılı veya
başarısız olmasına neden olabilir. (Orijinal değerler, istek FilterChainProxy'den çıktıktan sonra uygulama tarafından
hala kullanılabilir durumda olacaktır.) Gelen URL'de diğer farklılıklar da mümkündür. Örneğin, path-traversal
dizileri (/../ gibi) veya birden çok ileri eğik çizgi (//), pattern eşleşmelerinin başarısız olmasına neden olabilir.
Bazı konteynerlar, servlet eşlemesini yapmadan önce bunları normalize ederken, diğerleri etmez.Bu tür sorunlara karşı
korunmak için, FilterChainProxy, isteği kontrol etmek ve sarmalamak için bir HttpFirewall stratejisi kullanır.
Varsayılan olarak, normalize edilmemiş istekler otomatik olarak reddedilir ve pattern eşleştirmesi için path
parametreleri ve yinelenen eğik çizgiler kaldırılır. (Örneğin, /secure;hack=1/somefile.html;hack=2 şeklindeki orijinal
bir istek path'ini /secure/somefile.html olarak döndürülür.) Bu nedenle, güvenlik filtre zincirini yönetmek için bir
FilterChainProxy kullanmak önemlidir. Dikkat edilmesi gereken nokta, servletPath ve pathInfo değerlerinin konteyner
tarafından çözümlendiğidir, bu nedenle uygulamanızın, pattern eşleştirmesi için bu bölümler kaldırıldığı için yarı
noktalı virgül içeren geçerli pathler içermemesi önemlidir.

Yukarıda belirtildiği gibi, varsayılan strateji, eşleştirme için Ant tarzı yolları kullanmaktır ve bu, çoğu kullanıcı
için en iyi seçenek olacaktır. Strateji, AntPathRequestMatcher sınıfında uygulanır ve Spring'in AntPathMatcher'ını
kullanarak pattern'i büyük-küçük harf duyarsız bir şekilde servletPath ve pathInfo'nun birleştirilmiş haliyle
eşleştirirken queryString'i dikkate almaz.

Daha güçlü bir eşleme stratejisine ihtiyacınız varsa normal expression'lar kullanabilirsiniz. Strateji implementasyonu
daha sonra RegexRequestMatcher olur.

Pratikte, uygulamanıza erişimi kontrol etmek için web uygulaması düzeyinde tanımlanan güvenlik kısıtlamalarına tamamen
güvenmek yerine, hizmet katmanında method güvenliğini kullanmanızı öneririz. URL'ler değişebilir ve bir uygulamanın
destekleyebileceği tüm olası URL'leri ve isteklerin nasıl manipüle edilebileceğini hesaba katmak zor olabilir.
Anlaşılması kolay birkaç basit Ant yolunu kullanmakla sınırlı olmanızı öneririz. Her zaman "varsayılan olarak reddetme"
yaklaşımını kullanmaya çalışın, yani erişimi reddetmek için en sona bir yakalama (*) karakteri ekleyin.

Service Layer'da tanımlanan güvenlik, daha güçlü ve atlanması daha zor bir yapıya sahip olduğundan, Spring Security'nin
method güvenliği seçeneklerinden her zaman yararlanmanız önerilir. Bu sayede daha güvenli bir uygulama
geliştirebilirsiniz.

HttpFirewall, HTTP response header'larında ki yeni satır karakterlerini reddederek HTTP Response Splitting'i önler. Bu,
potansiyel bir güvenlik açığı olan HTTP Response Splitting saldırılarını engeller. HttpFirewall, gelen HTTP isteklerini
ve yanıtları filtrelemek için kullanılan bir bileşendir ve güvenliğinizi artırmak için önemli bir katmandır.

Varsayılan olarak, StrictHttpFirewall implementasyonu kullanılır. Bu implementasyon, kötü niyetli görünen request'leri
reddeder. İhtiyaçlarınız için çok katı ise, hangi tür isteklerin reddedileceğini özelleştirebilirsiniz. Ancak bunu
yaparken, bu durumun uygulamanızı saldırılara açabileceğini bilerek yapmanız önemlidir. Örneğin, Spring MVC'nin matris
değişkenlerini kullanmak istiyorsanız, aşağıdaki yapılandırmayı kullanabilirsiniz:

Allow Matrix Variables:

```
@Bean
public StrictHttpFirewall httpFirewall() {
    StrictHttpFirewall firewall = new StrictHttpFirewall();
    firewall.setAllowSemicolon(true);
    return firewall;
}
```

Cross Site Tracing (XST) ve HTTP Verb Tampering saldırılarına karşı korunmak için StrictHttpFirewall, izin verilen
geçerli HTTP methodlarının bir izin listesi sağlar. Varsayılan geçerli methodlar DELETE, GET, HEAD, OPTIONS, PATCH, POST
ve PUT'tur. Uygulamanızın geçerli yöntemleri değiştirmesi gerekiyorsa, özel bir StrictHttpFirewall bean'i
yapılandırabilirsiniz. Aşağıdaki örnek yalnızca HTTP GET ve POST methodlarına izin verir:

Allow Only GET & POST:

```
@Bean
public StrictHttpFirewall httpFirewall() {
    StrictHttpFirewall firewall = new StrictHttpFirewall();
    firewall.setAllowedHttpMethods(Arrays.asList("GET", "POST"));
    return firewall;
}
```

Eğer new MockHttpServletRequest() kullanıyorsanız, bu şu anda boş bir String ("") olarak bir HTTP methodu oluşturur. Bu
geçersiz bir HTTP methodudur ve Spring Security tarafından reddedilir. Bu sorunu çözmek için onu new
MockHttpServletRequest("GET", "") ile değiştirebilirsiniz. Bu konuda iyileştirme talep eden bir sorun için SPR_16851'ı
inceleyebilirsiniz.

Eğer herhangi bir HTTP methoduna izin vermek zorundaysanız (tavsiye edilmez),
StrictHttpFirewall.setUnsafeAllowAnyHttpMethod(true) methodunu kullanabilirsiniz. Bu, HTTP methodunun doğrulamasını
tamamen devre dışı bırakır. Bununla birlikte, herhangi bir HTTP methoduna izin vermek, güvenlik riski oluşturabilir ve
bu nedenle dikkatli olmanız önemlidir.

StrictHttpFirewall, header adlarını ve değerlerini, parametre adlarını da kontrol eder. Her karakterin tanımlanmış bir
kod noktasına sahip olması ve kontrol karakteri olmaması gerekmektedir. Bu sayede, güvenliğinizi artırmak için gelen
isteklerin header, değer ve parametrelerini doğru bir şekilde denetleyebilirsiniz. Böylece potansiyel saldırıları
önleyebilir ve güvenlik açıklarını en aza indirebilirsiniz. Bu gereklilik, aşağıdaki yöntemler kullanılarak gerektiğinde
gevşetilebilir veya ayarlanabilir:

- StrictHttpFirewall#setAllowedHeaderNames(Predicate)
- StrictHttpFirewall#setAllowedHeaderValues(Predicate)
- StrictHttpFirewall#setAllowedParameterNames(Predicate)

Parameter değerleri, setAllowedParameterValues(Predicate) methodu ile de kontrol edilebilir.

Örneğin, bu kontrolü devre dışı bırakmak için StrictHttpFirewall'inizi her zaman true döndüren Predicate örnekleriyle
yapılandırabilirsiniz. Bu, tüm parametre değerlerinin geçerli olarak kabul edileceği anlamına gelir. Bununla birlikte,
bu kontrolü devre dışı bırakmanın potansiyel güvenlik açıklarına neden olabileceğini unutmamak önemlidir, bu nedenle
dikkatli olunmalıdır.

Allow Any Header Name, Header Value, and Parameter Name:

```
@Bean
public StrictHttpFirewall httpFirewall() {
    StrictHttpFirewall firewall = new StrictHttpFirewall();
    firewall.setAllowedHeaderNames((header) -> true);
    firewall.setAllowedHeaderValues((header) -> true);
    firewall.setAllowedParameterNames((parameter) -> true);
    return firewall;
}
```

Bunun yerine, izin vermeniz gereken belirli bir değer olabilir. Bu durumda, setAllowedParameterValues() methodunu
kullanarak yalnızca belirli bir değeri kabul edecek şekilde yapılandırabilirsiniz.

Örneğin, iPhone Xʀ gibi cihazlar, ISO-8859-1 karakter setinde bulunmayan bir karakteri içeren bir User-Agent kullanır.
Bu nedenle, bazı uygulama sunucuları bu değeri iki ayrı karakter olarak ayrıştırır, ikincisi tanımlanmamış bir karakter
olur.

Bunu setAllowedHeaderValues methoduyla çözebilirsiniz:

Allow Certain User Agents:

```
@Bean
public StrictHttpFirewall httpFirewall() {
    StrictHttpFirewall firewall = new StrictHttpFirewall();
    Pattern allowed = Pattern.compile("[\\p{IsAssigned}&&[^\\p{IsControl}]]*");
    Pattern userAgent = ...;
    firewall.setAllowedHeaderValues((header) -> allowed.matcher(header).matches() || userAgent.matcher(header).matches());
    return firewall;
}
```

Header values için, bunları doğrulama zamanında UTF-8 olarak ayrıştırmayı düşünebilirsiniz. Böylece ISO-8859-1
karakter setinin sınırlamalarını aşabilir ve daha geniş bir karakter yelpazesini destekleyebilirsiniz.

Parse Headers As UTF-8:

```
firewall.setAllowedHeaderValues((header) -> {
    String parsed = new String(header.getBytes(ISO_8859_1), UTF_8);
    return allowed.matcher(parsed).matches();
});
```