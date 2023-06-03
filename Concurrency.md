# Concurrency Support

Çoğu ortamda, Security bilgisi Thread bazında saklanır. Bu, yeni bir Thread üzerinde işlem yapıldığında SecurityContext
kaybedildiği anlamına gelir. Spring Security, bu durumu daha kolay yönetilebilmesi için bazı altyapıları sağlar.
Spring Security, multi-thread ortamlarda Spring Security ile çalışmayı desteklemek için düşük seviye abstaction'lar
sunar. Aslında, bu, Spring Security'nin AsyncContext.start(Runnable) ve Spring MVC Async Integration ile entegre olmak
için kullandığı şeydir.

## DelegatingSecurityContextRunnable

Spring Security'nin concurrency desteği içindeki en temel yapı taşlarından biri, DelegatingSecurityContextRunnable'dir.
Bu, bir delegate Runnable'ı wrap eder ve delegate için belirtilen bir SecurityContext ile SecurityContextHolder'ı
başlatır. Ardından delegate Runnable'ı çağırır ve işlem tamamlandıktan sonra SecurityContextHolder'ı temizler.
DelegatingSecurityContextRunnable yaklaşık olarak aşağıdaki gibi görünür:

```
public void run() {
try {
	SecurityContextHolder.setContext(securityContext);
	delegate.run();
} finally {
	SecurityContextHolder.clearContext();
}
}
```

DelegatingSecurityContextRunnable, çok basit olmasına rağmen, SecurityContext'in bir Thread'den diğerine sorunsuz bir
şekilde aktarılmasını sağlar. Bu, çoğu durumda SecurityContextHolder'ın bir Thread bazında çalışmasının önemli olduğu
anlamına gelir. Örneğin, Spring Security'nin <global-method-security> desteğini kullanarak bir hizmetinizi güvence
altına alabilirsiniz. Şimdi, mevcut Thread'in SecurityContext'ini güvence altına alınan hizmeti çağıran Thread'e
aktarabilirsiniz. Aşağıdaki örnek, bunu nasıl yapabileceğinizi göstermektedir:

```
Runnable originalRunnable = new Runnable() {
public void run() {
	// invoke secured service
}
};

SecurityContext context = SecurityContextHolder.getContext();
DelegatingSecurityContextRunnable wrappedRunnable =
	new DelegatingSecurityContextRunnable(originalRunnable, context);

new Thread(wrappedRunnable).start();
```

Yukarıda ki kod bloğu:

- Güvence altına alınmış hizmetimizi çağıran bir Runnable oluştururuz. Bu Runnable'ın Spring Security'den haberi yoktur.
- SecurityContextHolder'dan kullanmak istediğimiz SecurityContext'i alır ve DelegatingSecurityContextRunnable'ı başlatır
- Bu şekilde, DelegatingSecurityContextRunnable'ı kullanarak SecurityContext'in geçişini sağlayan bir Thread
  oluşturulur. Bu Thread, güvence altına alınmış hizmetin çağrılmasını ve SecurityContext'in doğru bir şekilde
  taşınmasını sağlar.
- Oluşturduğumuz Thread'i başlatmak için start() yöntemini kullanabilirsiniz.

SecurityContextHolder'dan SecurityContext ile bir DelegatingSecurityContextRunnable oluşturmak yaygın olduğundan, bunun
için bir shortcut constructor bulunmaktadır. Aşağıdaki kod, önceki kodla aynı etkiye sahiptir:

```
Runnable originalRunnable = new Runnable() {
public void run() {
	// invoke secured service
}
};

DelegatingSecurityContextRunnable wrappedRunnable =
	new DelegatingSecurityContextRunnable(originalRunnable);

new Thread(wrappedRunnable).start();
```

Sahip olduğumuz kod kullanımı kolay olsa da, hala Spring Security kullandığımız bilgisini gerektirir. Bir sonraki
bölümde, DelegatingSecurityContextExecutor'ı nasıl kullanarak Spring Security kullandığımızı gizleyebileceğimize
bakacağız.

## DelegatingSecurityContextExecutor

Önceki bölümde, DelegatingSecurityContextRunnable'ın kullanımının kolay olduğunu, ancak onu kullanmak için Spring
Security hakkında bilgi sahibi olmamız gerektiğini gördük. Şimdi, DelegatingSecurityContextExecutor'ın kodumuzu Spring
Security kullanımından bağımsız hale getirerek nasıl koruyabileceğimize bakalım.

DelegatingSecurityContextExecutor, DelegatingSecurityContextRunnable ile benzer bir tasarıma sahiptir, ancak bir
delegate Runnable yerine bir delegate Executor kabul eder. İşte onu nasıl kullanacağımızı gösteren bir örnek:

```
SecurityContext context = SecurityContextHolder.createEmptyContext();
Authentication authentication =
	UsernamePasswordAuthenticationToken.authenticated("user","doesnotmatter", AuthorityUtils.createAuthorityList("ROLE_USER"));
context.setAuthentication(authentication);

SimpleAsyncTaskExecutor delegateExecutor =
	new SimpleAsyncTaskExecutor();
DelegatingSecurityContextExecutor executor =
	new DelegatingSecurityContextExecutor(delegateExecutor, context);

Runnable originalRunnable = new Runnable() {
public void run() {
	// invoke secured service
}
};

executor.execute(originalRunnable);
```

Bu kod:

Bu örnekte, SecurityContext'i elle oluşturuyoruz. Ancak, SecurityContext'i nereden veya nasıl elde ettiğimiz önemli
değildir (örneğin, SecurityContextHolder'dan alabiliriz). * Sunulan Runnable nesnelerini yürütmekle görevli bir
delegateExecutor oluşturulur. * Son olarak, execute yöntemine iletilen herhangi bir Runnable'ı
DelegatingSecurityContextRunnable ile wrap eden bir DelegatingSecurityContextExecutor oluşturulur.

Ardından, wrap eden Runnable'ı delegateExecutor'a iletiyor. Bu durumda, DelegatingSecurityContextExecutor'a sunulan her
Runnable için aynı SecurityContext kullanılır. Bu, artırılmış ayrıcalıklara sahip bir kullanıcı tarafından
çalıştırılması gereken arka plan görevlerini yürütürken güzeldir. * Şimdi, kendinize "Bu kodu nasıl Spring Security
hakkında bilgisiz hale getiriyor?" diye sorabilirsiniz. Kodumuzda SecurityContext'i ve
DelegatingSecurityContextExecutor'ı kendimiz oluşturmak yerine, zaten başlatılmış bir DelegatingSecurityContextExecutor
örneğini enjekte edebiliriz.

```
@Autowired
private Executor executor; // becomes an instance of our DelegatingSecurityContextExecutor

public void submitRunnable() {
Runnable originalRunnable = new Runnable() {
	public void run() {
	// invoke secured service
	}
};
executor.execute(originalRunnable);
}
```

Artık kodumuz, SecurityContext'in Thread'e iletilmesi, orijinal Runnable'ın çalıştırılması ve SecurityContextHolder'ın
temizlenmesi işlemlerinden habersizdir. Bu örnekte, her bir thread'i çalıştırmak için aynı kullanıcı kullanılıyor. Peki,
executor.execute(Runnable) yöntemini çağırdığımızda, orijinalRunnable'ı işlemek için SecurityContextHolder'daki
kullanıcıyı (yani, mevcut oturum açmış kullanıcıyı) kullanmak istersek ne yapabiliriz? Bunun için
DelegatingSecurityContextExecutor constructor'ından SecurityContext argümanını kaldırabilirsiniz:

```
SimpleAsyncTaskExecutor delegateExecutor = new SimpleAsyncTaskExecutor();
DelegatingSecurityContextExecutor executor =
	new DelegatingSecurityContextExecutor(delegateExecutor);
```

Şimdi, her executor.execute(Runnable) çalıştığında, SecurityContextHolder tarafından önce SecurityContext alınır ve
ardından bu SecurityContext kullanılarak DelegatingSecurityContextRunnable oluşturulur. Bu, Runnable'ımızı
executor.execute(Runnable) kodunu çağırmak için kullanılan kullanıcı ile çalıştırdığımız anlamına gelir.

## Spring Security Concurrency Classes

- DelegatingSecurityContextCallable
- DelegatingSecurityContextExecutor
- DelegatingSecurityContextExecutorService
- DelegatingSecurityContextRunnable
- DelegatingSecurityContextScheduledExecutorService
- DelegatingSecurityContextSchedulingTaskExecutor
- DelegatingSecurityContextAsyncTaskExecutor
- DelegatingSecurityContextTaskExecutor
- DelegatingSecurityContextTaskScheduler