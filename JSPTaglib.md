# JSP Tag Libraries

## Declaring the Taglib

Etiketlerden herhangi birini kullanmak için JSP dosyanızda security taglib'inin tanımlanmış olması gerekmektedir. (XML)

```
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
```

## The authorize Tag

Bu tag, içeriğinin değerlendirilip değerlendirilmeyeceğini belirlemek için kullanılır. Spring Security 3.0'da, bu tag
iki farklı şekilde kullanılabilir.

İlk yaklaşım, etiketin access attribute'unde belirtilen bir web-security expression kullanır. Expression
değerlendirmesi, application context'de tanımlanan SecurityExpressionHandler<FilterInvocation>'a (bu hizmetin
kullanılabilir olduğundan emin olmak için <http> ad alanı yapılandırmanızda web ifadelerini etkinleştirmeniz gerekir)
devredilir. Örneğin: (XML)

```
<sec:authorize access="hasRole('supervisor')">

This content will only be visible to users who have the "supervisor" authority in their list of <tt>GrantedAuthority</tt>s.

</sec:authorize>
```

Spring Security'nin PermissionEvaluator ile birlikte kullanıldığında, tag izinleri kontrol etmek için de
kullanılabilir. (XML)

```
<sec:authorize access="hasPermission(#domain,'read') or hasPermission(#domain,'write')">

This content will only be visible to users who have read or write permission to the Object found as a request attribute named "domain".

</sec:authorize>
```

Yaygın bir gereklilik, kullanıcının gerçekten tıklamaya izin verildiğinde yalnızca belirli bir bağlantının
gösterilmesidir. Bir şeyin önceden izin verilip verilmediğini nasıl belirleyebiliriz? Bu tag, ayrıca bir alternatif
modda çalışabilir ve belirli bir URL'yi bir attribute olarak tanımlamanıza olanak tanır. Kullanıcının o URL'yi çağırma
izni varsa, tag içeriği değerlendirilir. Aksi takdirde, atlanır. Bu durumda şöyle bir şeyiniz olabilir: (XML)

```
<sec:authorize url="/admin">

This content will only be visible to users who are authorized to send requests to the "/admin" URL.

</sec:authorize>
```

Bu tag'ı kullanmak için, application context de WebInvocationPrivilegeEvaluator bir instance'a sahip olmanız da
gerekmektedir. Eğer namespace'i kullanıyorsanız, otomatik olarak bir tane kaydedilir. Bu,
DefaultWebInvocationPrivilegeEvaluator'ın bir instance'idır ve sağlanan URL için bir sahte web request'i oluşturur ve
security interceptor'ını çağırarak isteğin başarılı olup olmayacağını kontrol eder. Bu, <http> namespace yapılandırması
içinde tanımlanan intercept-url bildirimlerini kullanarak access-control kurulumuna delegenize olanak tanır ve
JSP'lerinizde gerekli roller gibi bilgileri tekrarlamaktan kaçınır. Daha spesifik bir eşleşme için method
attribute'unu (POST gibi HTTP yöntemini) kullanarak bu yaklaşımı da birleştirebilirsiniz.

Tag'ın değerlendirilmesi sonucunda (erişimin verilip verilmediği) bir page context scope değişkeninde saklayabilirsiniz.
Bunun için var attribute'unu değişken adına ayarlamanız gerekmektedir. Bu şekilde, koşulu sayfanın diğer noktalarında
tekrar çoğaltma ve yeniden değerlendirme ihtiyacını ortadan kaldırabilirsiniz.

### Disabling Tag Authorization for Testing

Yetkisiz kullanıcılar için sayfada bir bağlantıyı gizlemek, onların URL'ye erişimini engellemez. Örneğin, doğrudan
tarayıcılarına yazabilirler. Test sürecinin bir parçası olarak, bağlantıların gerçekten backend'de güvence altına
alındığını kontrol etmek için gizli alanları ortaya çıkarmak isteyebilirsiniz. Eğer spring.security.disableUISecurity
sistem özelliğini true olarak ayarlarsanız, authorize etiketi hala çalışır ancak içeriğini gizlemez. Varsayılan olarak,
içeriği <span class="securityHiddenUI">_</span> tag ile çevreler. Bu, belirli bir CSS stilini (örneğin, farklı
bir arka plan rengi) kullanarak "gizli" içeriği görüntülemenizi sağlar.

spring.security.securedUIPrefix ve spring.security.securedUISuffix özelliklerini ayarlayarak, varsayılan span
etiketlerinden çevreleyen metni değiştirebilirsiniz (veya tamamen kaldırmak için boş dize kullanabilirsiniz).

## The Authentication Tag

Bu tag, security context'de depolanan mevcut Authentication nesnesine erişime izin verir. Bu tag, nesnenin bir
özelliğini doğrudan JSP'de render eder. Örneğin, Authentication'ın principal özelliği Spring Security'nin UserDetails
nesnesinin bir örneği ise, <sec:authentication property="principal.username" /> kullanarak mevcut kullanıcının adını
render edebilirsiniz.

Tabii ki, bu tür işlemler için JSP tag'larını kullanmak zorunlu değildir ve bazı insanlar görünümde mümkün olduğunca
az mantık tutmayı tercih eder. MVC controller'da Authentication nesnesine erişebilirsiniz

## The accesscontrollist Tag

Bu tag, yalnızca Spring Security'nin ACL modülü ile kullanıldığında geçerlidir. Belirtilen bir domain nesnesi
için gereken izinlerin virgülle ayrılmış bir listesini kontrol eder. Eğer mevcut kullanıcının tüm bu izinlere sahipse,
tag içeriği değerlendirilir. Eğer izinlere sahip değilse, atlanır. (XML)

```
<sec:accesscontrollist hasPermission="1,2" domainObject="${someObject}">

<!-- This will be shown if the user has all of the permissions represented by the values "1" or "2" on the given object. -->

</sec:accesscontrollist>
```

İzinler, application context'de tanımlanan PermissionFactory'ye iletilerek ACL İzin örneklerine dönüştürülür, bu nedenle
fabrika tarafından desteklenen herhangi bir biçim olabilirler. İzinlerin tamsayılar olması gerekmez. Bunlar, READ veya
WRITE gibi dizeler olabilir. Eğer bir PermissionFactory bulunamazsa, DefaultPermissionFactory'nin bir örneği kullanılır.
Application Context'de ki AclService, sağlanan nesne için Acl örneğini yüklemek için kullanılır. Acl, gerekli izinlerle
çağrılır ve bunlardan tümü sağlanıp sağlanmadığını kontrol eder.

Bu tag, authorize tag'ı ile aynı şekilde var attribute'unu de desteklemektedir.

## The csrfInput Tag

CSRF koruması etkinleştirildiyse, bu tag CSRF protection token'ı için doğru isim ve değeri içeren gizli bir form alanı
ekler. CSRF koruması etkinleştirilmediyse, bu tag hiçbir çıktı vermez.

Normalde, Spring Security, form:form tag'larını kullandığınızda otomatik olarak bir CSRF form alanı ekler. Ancak,
herhangi bir nedenle form:form kullanamazsanız, csrfInput tag'ı kullanışlı bir yerine geçme seçeneğidir.

Bu tag'ı, genellikle diğer giriş alanlarını yerleştirdiğiniz HTML <form></form> bloğu içine yerleştirmelisiniz. Bu
etiketi, Spring <form:form></form:form> bloğu içine yerleştirmeyin, çünkü Spring Security, Spring formlarını otomatik
olarak işler. (XML)

```
	<form method="post" action="/do/something">
		<sec:csrfInput />
		Name:<br />
		<input type="text" name="name" />
		...
	</form>
```

## The csrfMetaTags Tag

CSRF koruması etkinleştirildiyse, bu tag, CSRF koruma token form alanı ve header name'leri içeren meta tag'larını
ve CSRF koruma token değerini ekler. Bu meta tag'ları, uygulamanızdaki JavaScript içinde CSRF korumasını kullanmak
için faydalıdır.

csrfMetaTags tag'ini genellikle diğer meta tag'larını yerleştirdiğiniz HTML <head></head> bloğu içine
yerleştirmelisiniz. Bu tag'ı kullandıktan sonra, JavaScript kullanarak form alanı adına, header adına ve token
değerine erişebilirsiniz. Bu örnekte, görevi kolaylaştırmak için JQuery kullanılmıştır. Aşağıdaki bir örnek
gösterilmektedir: (XML)

```
<!DOCTYPE html>
<html>
	<head>
		<title>CSRF Protected JavaScript Page</title>
		<meta name="description" content="This is the description for this page" />
		<sec:csrfMetaTags />
		<script type="text/javascript" language="javascript">

			var csrfParameter = $("meta[name='_csrf_parameter']").attr("content");
			var csrfHeader = $("meta[name='_csrf_header']").attr("content");
			var csrfToken = $("meta[name='_csrf']").attr("content");

			// using XMLHttpRequest directly to send an x-www-form-urlencoded request
			var ajax = new XMLHttpRequest();
			ajax.open("POST", "https://www.example.org/do/something", true);
			ajax.setRequestHeader("Content-Type", "application/x-www-form-urlencoded data");
			ajax.send(csrfParameter + "=" + csrfToken + "&name=John&...");

			// using XMLHttpRequest directly to send a non-x-www-form-urlencoded request
			var ajax = new XMLHttpRequest();
			ajax.open("POST", "https://www.example.org/do/something", true);
			ajax.setRequestHeader(csrfHeader, csrfToken);
			ajax.send("...");

			// using JQuery to send an x-www-form-urlencoded request
			var data = {};
			data[csrfParameter] = csrfToken;
			data["name"] = "John";
			...
			$.ajax({
				url: "https://www.example.org/do/something",
				type: "POST",
				data: data,
				...
			});

			// using JQuery to send a non-x-www-form-urlencoded request
			var headers = {};
			headers[csrfHeader] = csrfToken;
			$.ajax({
				url: "https://www.example.org/do/something",
				type: "POST",
				headers: headers,
				...
			});

		<script>
	</head>
	<body>
		...
	</body>
</html>
```

CSRF koruması etkinleştirilmemişse, csrfMetaTags hiçbir çıktı vermez.

