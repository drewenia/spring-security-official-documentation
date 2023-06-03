# Localization

Eğer farklı yerel ayarları (locales) desteklemek isterseniz, bu bölüm size ihtiyacınız olan her şeyi sağlar.

Tüm exception mesajları, authentication failure ve erişimin reddedilmesi gibi mesajlar da dahil olmak üzere,
yerelleştirilebilir. Devoloperlara veya system developers'lara odaklanan exceptionlar ve loglama mesajları (incorrect
attributes'ler, interface contract violations, incorrect constructor'lar, startup time validation, error exception
düzeyinde loglama gibi) localize edilmekte ve Spring Security'nin kodu içinde İngilizce olarak sabitlenmektedir.

spring-security-core-xx.jar içinde, org.springframework.security paketini bulursunuz. Bu paket, messages.properties
dosyasını ve yaygın diller için yerelleştirilmiş sürümlerini içerir. ApplicationContext'niz, Spring Security
sınıflarının Spring'in MessageSourceAware arabirimini uygulaması nedeniyle bunlara başvurmalıdır ve message resolver'ın
application context başlatma zamanında bağımlılık olarak enjekte edilmesini bekler. Genellikle yapmanız gereken tek şey,
application context'iniz de bir bean kaydetmek ve mesajlara başvurmak için kullanmaktır. Aşağıdaki örnek bir örneği
göstermektedir: (XML)

```
<bean id="messageSource"
	class="org.springframework.context.support.ReloadableResourceBundleMessageSource">
<property name="basename" value="classpath:org/springframework/security/messages"/>
</bean>
```

The messages.properties dosyası, standart resource bundles'lara uygun olarak adlandırılır ve Spring Security
mesajlarının desteklediği varsayılan dilin temsilcisidir. Bu varsayılan dosya İngilizce'dir.

messages.properties dosyasını özelleştirmek veya başka dilleri desteklemek için, dosyayı kopyalayıp uygun şekilde
yeniden adlandırmalı ve yukarıda verilen bean tanımına kaydetmelisiniz. Bu dosyanın içinde çok sayıda mesaj key'i
bulunmadığından, lokalizasyon büyük bir inisiyatif olarak düşünülmemelidir. Eğer bu dosyanın lokalizasyonunu
gerçekleştirirseniz, çalışmanızı toplulukla paylaşmak için uygun şekilde adlandırılmış yerelleştirilmiş versiyonunu
messages.properties dosyasına ekleyerek JIRA görevi oluşturmanızı düşünebilirsiniz.

Spring Security, uygun mesajı aramak için Spring'in lokalizasyon desteğine dayanır. Bunun çalışabilmesi için, gelen
isteğin dil bilgisinin Spring'in org.springframework.context.i18n.LocaleContextHolder içinde saklandığından emin olmanız
gerekir. Spring MVC'nin DispatcherServlet'i bunu otomatik olarak uygulamanız için yapar. Ancak, Spring Security'nin
filtreleri bundan önce çağrıldığından, LocaleContextHolder'ın filtreler çağrılmadan önce doğru Locale'ı içermesi
gerekmektedir. Bunu bir filtrede kendiniz yapabilirsiniz (bu filtre, web.xml'deki Spring Security filtrelerinden önce
gelmelidir) veya Spring'in RequestContextFilter'ını kullanabilirsiniz. 