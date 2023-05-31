# Domain Object Security (ACLs)

Bu bölüm, Spring Security'nin Erişim Kontrol Listeleri (ACL) ile domain object security sağladığını açıklar. ACL'ler,
kullanıcıların belirli domain nesnelerine erişim haklarını kontrol etmek için kullanılır. Spring Security, bu ACL
mekanizmasını kullanarak domain nesneleri üzerinde granüler düzeyde yetkilendirme sağlar.

Karmaşık uygulamalar genellikle web request veya method çağrısı seviyesindeki erişim izinlerini aşan erişim izinleri
tanımlamak ihtiyacı duyar. Güvenlik kararları, kimin (Authentication), nerede (MethodInvocation) ve neyi
(SomeDomainObject) olduğunu içermelidir. Başka bir deyişle, yetkilendirme kararları, method çağrısının konusu olan
gerçek alan nesne örneğini de dikkate almalıdır.

Hayal edin, bir evcil hayvan kliniği için bir uygulama tasarlıyorsunuz. Spring tabanlı uygulamanızın iki ana kullanıcı
grubu vardır: evcil hayvan kliniğinin çalışanları ve kliniğin müşterileri. Çalışanlar, tüm verilere erişebilmelidir,
müşterileriniz ise sadece kendi müşteri kayıtlarını görebilmelidir. Biraz daha ilginç hale getirmek için,
müşterileriniz, "yavru köpek okulu" mentorları veya yerel "Pony Kulübü" başkanı gibi diğer kullanıcıların müşteri
kayıtlarını görmesine izin verebilir. Spring Security'yi temel aldığınızda, birkaç farklı yaklaşımınız vardır:

- Güvenliği sağlamak için business methodlarınızı yazın. Erişimi olan kullanıcıları belirlemek için, Customer domain
  object içindeki bir koleksiyona danışabilirsiniz. SecurityContextHolder.getContext().getAuthentication() kullanarak
  Authentication nesnesine erişebilirsiniz.
- Güvenliği sağlamak için GrantedAuthority[] instance'larında ki izinlerden yararlanmak için bir AccessDecisionVoter
  yazabilirsiniz. AuthenticationManager'ın, başlıca (kullanıcı) tarafından erişimi olan her Customer domain object
  nesnesini temsil etmek için Authentication nesnesini özel GrantedAuthority[] nesneleriyle doldurması gerekmektedir.
- Güvenliği uygulamak ve hedef Customer domain object nesnesini doğrudan açmak için bir AccessDecisionVoter yazın. Bu
  durumda, voter'in, Customer nesnesini alabilmesi için bir DAO'ya (Veri Erişim Nesnesi) erişim sağlaması gerekmektedir.
  Daha sonra voter, Customer nesnesinin onaylanmış kullanıcılar koleksiyonuna erişebilir ve uygun kararı verebilir.

Her iki yaklaşım da tamamen geçerlidir. Ancak, ilk yaklaşım yetkilendirme kontrolünü business kodunuza bağlar. Bu
yaklaşımın temel sorunları arasında birim testlerinin daha zor olması ve Customer yetkilendirme mantığının başka bir
yerde yeniden kullanılmasının daha zor olması yer almaktadır. Authentication nesnesinden GrantedAuthority[]
instance'larını elde etmek de geçerli bir yöntemdir, ancak büyük sayıda Customer nesnesine ölçeklendirilemez. Bir
kullanıcının 5.000 Customer nesnesine erişebilmesi (bu durumda pek olası olmasa da, büyük bir At Kulübü için düşünün!)
durumunda, Authentication nesnesinin oluşturulması için gereken bellek tüketimi ve zaman korkunç olabilir. Bu tür
senaryolarda, Authentication nesnesini oluşturmak ve yönetmek için daha hafif ve daha ölçeklenebilir bir yaklaşım
kullanmanız önerilir. Bu yaklaşım, Authentication nesnesinin içindeki yetkilerin dinamik olarak oluşturulmasını sağlar
ve bellek tüketimini ve oluşturma süresini minimize eder. Bunun için, yetkilendirme mekanizmasını gerektiğinde
sorgulayabilen bir yetkilendirme hizmeti kullanabilirsiniz. Bu hizmet, kullanıcının erişim izinlerini dinamik olarak
alır ve Authentication nesnesine ekler. Örneğin, bir kullanıcının erişebileceği Customer nesnelerinin kimliklerini tutan
bir veritabanı tablosu kullanabilirsiniz. Yetkilendirme hizmeti, kullanıcının kimliğiyle bu tabloya erişip, ilgili
Customer nesnelerinin kimliklerini belirler ve Authentication nesnesine ekler.
Böylece, her seferinde tüm Customer nesneleri için GrantedAuthority[] örneklerini oluşturmak yerine, sadece kullanıcının
erişebileceği Customer nesnelerinin kimliklerini dinamik olarak alırsınız. Bu, bellek tüketimini ve oluşturma süresini
büyük ölçüde azaltır ve işlemi daha hafif hale getirir.

Bu yaklaşım, endişelerin ayrıştırılmasını sağlar ve bellek veya CPU döngüleri kötüye kullanılmaz, ancak hem
AccessDecisionVoter hem de sonuçta iş mantığı metodunun, Customer nesnesini almakla sorumlu olan DAO'ya bir çağrı
yapması açısından hala verimsizdir. Her bir method çağrısı için iki erişim yapmak açıkça istenmeyen bir durumdur.
Ayrıca, listelenen her yaklaşımda, kendi erişim kontrol listesi (ACL) kalıcılığı ve business kodunu sıfırdan yazmanız
gerekmektedir.

## Key Concepts

Spring Security'nin ACL hizmetleri, spring-security-acl-xxx.jar adlı bir JAR dosyası içinde sağlanır. Spring
Security'nin domain nesnesi örneği güvenlik yeteneklerini kullanmak için bu JAR dosyasını classpath'inize eklemeniz
gerekmektedir.

Spring Security'nin domain nesnesi örneği güvenlik yetenekleri, erişim kontrol listesi (ACL) kavramına dayanmaktadır.
Sistemdeki her domain nesnesi örneği kendi ACL'sine sahiptir ve ACL, hangi kullanıcıların bu domain nesnesiyle
çalışabileceği ve hangilerinin çalışamayacağı gibi detayları kaydeder. Bu bağlamda, Spring Security uygulamanıza üç
temel ACL ile ilgili yetenek sağlar:

- Tüm domain nesneleriniz için ACL girişlerini verimli bir şekilde almanın (ve bu ACL'leri değiştirmenin) bir yolu
- Methodlar çağrılmadan önce belirli bir principal'ın nesnelerinizle çalışmasına izin verilmesini sağlamanın bir yolu
- Principal, methodlar çağrıldıktan sonra nesnelerinizle (veya döndürdükleri bir şeyle) çalışmasına izin verilmesini
  sağlamanın bir yolu

Bahsedilen ilk maddeye göre, Spring Security ACL modülünün temel yeteneklerinden biri, ACL'leri almanın yüksek
performanslı bir yolunu sağlamaktır. Bu ACL depolama yeteneği son derece önemlidir, çünkü sistemdeki her domain nesnesi
örneği birkaç erişim kontrol girişi içerebilir ve her ACL, diğer ACL'lerden miras alabilir ve ağaç benzeri bir yapıda
olabilir (bu, Spring Security tarafından desteklenir ve yaygın olarak kullanılır). Spring Security'nin ACL yeteneği,
ACL'leri yüksek performanslı bir şekilde almak için özenle tasarlanmış olup, tak-çıkar önbellekleme, veritabanı
güncellemelerinde deadlock'u en aza indirme, ORM frameworklerine bağımsızlık (doğrudan JDBC kullanımı), uygun
kapsülleme ve şeffaf veritabanı güncellemeleri gibi özellikleri içerir.

Spring Security ACL modülünün işleyişi için veritabanlarının merkezi bir öneme sahip olduğu göz önünde
bulundurulduğunda, varsayılan olarak kullanılan dört ana tabloyu incelememiz gerekmektedir. Tablolar, tipik bir Spring
Security ACL deployment'larında genellikle sıralı olarak boyuta göre listelenir ve en fazla satıra sahip olan tablo en
sona yerleştirilir:

- ACL_SID tablosu, sistemdeki herhangi bir ilgili veya yetkiyi unique bir şekilde tanımlamamızı sağlar
  ("SID", "Security IDentity"nin kısaltmasıdır). Tek sütunlar ID, SID'in metinsel temsilidir ve metinsel temsilin bir
  principal adına mı yoksa bir GrantedAuthority'ye mi işaret ettiğini belirten bir flag içerir. Bu nedenle, her unique
  principal veya GrantedAuthority için tek bir satır bulunur. Bir izin almak context'de kullanıldığında, SID
  genellikle "recipient" olarak adlandırılır.
- ACL_CLASS tablosu, sistemdeki herhangi bir domain nesnesi sınıfını unique bir şekilde tanımlamamızı sağlar. Tek
  sütunlar ID ve Java sınıf adıdır. Bu nedenle, saklamak istediğimiz her unique Class için tek bir satır bulunur.
- ACL_OBJECT_IDENTITY tablosu, sistemdeki her unique domain nesnesi örneği için bilgileri depolar. Sütunlar arasında
  ID, ACL_CLASS tablosuna bir foreign key, ACL_CLASS örneği için bilgi sağladığımızı bildiren unique bir
  tanımlayıcı, parent (ebeveyn), domain nesnesi örneğinin sahibini temsil etmek için ACL_SID tablosuna bir foreign
  key ve ACL girişlerinin herhangi bir üst ACL'den miras almasına izin verip vermediği bulunur. ACL izinlerini
  saklamak istediğimiz her bir domain nesnesi örneği için tek bir satırımız vardır.
- ACL_ENTRY tablosu, her alıcıya atanmış olan bireysel izinleri depolar. Sütunlar arasında ACL_OBJECT_IDENTITY tablosuna
  bir foreing key, alıcıyı temsil eden (yani ACL_SID için bir foreing key), denetim yapılıp yapılmayacağı ve
  verilen veya reddedilen gerçek izni temsil eden tam sayı bit maskesi bulunur. Bir alanın bir domain nesnesiyle
  çalışması için izin alan her bir alıcı için bir satırımız vardır.

Son paragrafta belirtildiği gibi, ACL sistemi tam sayı bit maskelemesini kullanır. Ancak, ACL sistemi kullanmak için bit
kaydırma konusunda detaylı bilgiye sahip olmanız gerekmez. Sadece, açabilir veya kapatabileceğimiz 32 bitimizin olduğunu
bilmek yeterlidir. Her bir bit, bir izni temsil eder. Varsayılan olarak, izinler okuma (bit 0), yazma (bit 1),
oluşturma (bit 2), silme (bit 3) ve yönetme (bit 4) olarak belirlenmiştir. Başka izinler kullanmak isterseniz kendi İzin
örneğinizi uygulayabilirsiniz ve ACL framework'unun geri kalanı, uzantılarınızın bilgisi olmadan çalışır.

Sistemdeki domain nesnelerinin sayısı, tam sayı bit maskelemesini kullanma tercihimizle hiçbir ilgisi olmadığını
anlamanız önemlidir. İzinler için 32 bitiniz olsa da, milyarlarca domain nesnesine sahip olabilirsiniz (bu da
ACL_OBJECT_IDENTITY ve muhtemelen ACL_ENTRY tablolarında milyarlarca satır demektir). Bu noktayı vurgulamamızın sebebi,
bazen insanların her potansiyel domain nesnesi için bir bit gerektiğini yanlışlıkla düşünmeleridir, ancak bu doğru
değildir.

ACL sisteminin temel işleyişini ve tablo yapılarına ilişkin bir genel bakış sağladıktan sonra, ana interface'leri
keşfetmemiz gerekiyor:

- Acl (Erişim Kontrol Listesi): Her bir domain nesnesinin yalnızca bir tane Acl nesnesi vardır ve bu nesne içinde
  AccessControlEntry (Erişim Kontrol Girişi) nesnelerini tutar ve Acl'nin sahibini bilir. Bir Acl, doğrudan domain
  nesnesine değil, ObjectIdentity (Nesne Kimliği) üzerinden işaret eder. Acl, ACL_OBJECT_IDENTITY tablosunda depolanır.
- AccessControlEntry (Erişim Kontrol Girişi): Bir Acl, genellikle framework içinde ACE (AccessControlEntry) olarak
  kısaltılan birden fazla AccessControlEntry nesnesini içerir. Her bir ACE, belirli bir İzin (Permission), Sid ve Acl
  üçlüsüne işaret eder. Bir ACE ayrıca izin verme veya izin vermeme durumunda olabilir ve denetim ayarlarını içerebilir.
  ACE, ACL_ENTRY tablosunda depolanır.
- Permission (İzin): Bir izin, belirli bir değişmez bit maskesini temsil eder ve bit maskesini kullanmak ve bilgi
  çıktısı oluşturmak için kolaylık fonksiyonları sunar. Yukarıda sunulan temel izinler (bit 0 ile bit 4 arası)
  BasePermission sınıfında bulunur.
- Sid (Güvenlik Kimliği): ACL modülü, özne (principal) ve GrantedAuthority[] örneklerine ihtiyaç duyar. Bu örnekler
  arasında indirekt bir seviye sağlamak için Sid arabirimini kullanır. ("SID", "Security IDentity" kavramının
  kısaltmasıdır.) Ortak sınıflar arasında PrincipalSid (bir Authentication nesnesi içindeki özneyi temsil etmek için) ve
  GrantedAuthoritySid bulunur. Güvenlik kimlik bilgileri ACL_SID tablosunda saklanır.
- ObjectIdentity (Nesne Kimliği): Her bir domain nesnesi, ACL modülü içinde bir ObjectIdentity ile temsil edilir.
  Varsayılan implementasyon ObjectIdentityImpl olarak adlandırılır.
- AclService (AclServisi): Belirli bir ObjectIdentity için geçerli olan Acl'yi alır. Dahil edilen uygulamada
  (JdbcAclService), alım işlemleri bir LookupStrategy'ye devredilir. LookupStrategy, ACL bilgilerini almak için yüksek
  optimize edilmiş bir strateji sağlar. Batched retrievals (BasicLookupStrategy) kullanarak ve materyalize görünümler,
  hiyerarşik sorgular ve benzeri performans odaklı, ANSI SQL dışındaki özel uygulamaları destekler.
- MutableAclService (DeğiştirilebilirAclServisi): Değiştirilmiş bir Acl'nin kalıcılık için sunulmasını sağlar. Bu
  interface'in kullanımı isteğe bağlıdır.

Dikkat edilmesi gereken nokta, AclService ve ilgili veritabanı sınıflarımızın hepsinin ANSI SQL kullandığıdır. Bu
nedenle, bu sistem büyük veritabanlarıyla uyumlu çalışmalıdır. Yazıldığı zaman, sistem Hypersonic SQL, PostgreSQL,
Microsoft SQL Server ve Oracle ile başarılı bir şekilde test edilmiştir. Bu nedenle, bu ana veritabanı sistemlerinden
herhangi birini kullanıyorsanız, Spring Security ACL modülü ile uyumluluk sağlamak için ANSI SQL desteğine sahip
olduğunuzdan emin olabilirsiniz.

## Getting Started

Spring Security'nin ACL özelliğini kullanmaya başlamak için ACL bilgilerinizi bir yerde depolamanız gerekmektedir. Bunun
için öncelikle Spring içinde bir DataSource örneği oluşturmanız gerekmektedir. DataSource daha sonra
JdbcMutableAclService (Değiştirilebilir Acl Servisi) ve BasicLookupStrategy (Temel Arama Stratejisi) örneklerine enjekte
edilir. İlki değişiklik yapma yetenekleri sağlar, ikincisi ise yüksek performanslı ACL alım yetenekleri sağlar. Spring
Security ile birlikte gelen örneklerden birini inceleyerek bir yapılandırma örneği görebilirsiniz. Ayrıca, önceki
bölümde listelenen dört ACL özel tabloyu veritabanına doldurmanız gerekmektedir (uygun SQL ifadeleri için ACL
örneklerine bakınız). Bu işlemleri gerçekleştirerek Spring Security ACL yeteneklerini kullanmaya başlayabilirsiniz.

Gerekli şemayı oluşturduktan ve JdbcMutableAclService'yi örnekledikten sonra, domain modelinizin Spring Security ACL
paketiyle uyumlu olduğundan emin olmanız gerekmektedir. Umarız ObjectIdentityImpl yeterli olacaktır, çünkü birçok farklı
şekilde kullanılabilmektedir. Çoğu kişinin domain nesneleri, public Serializable getId() metodunu içerir. Eğer bu
metodun dönüş tipi long veya long ile uyumlu bir tipse (örneğin int gibi), ObjectIdentity konularını daha fazla
düşünmeniz gerekmemektedir. ACL modülünün birçok parçası long kimliklere dayanmaktadır. Eğer long veya long ile uyumlu
bir tip (int, byte vb.) kullanmıyorsanız, muhtemelen birkaç sınıfı yeniden uygulamanız gerekecektir. Spring Security'nin
ACL modülünde long olmayan kimliklere destek yoktur, çünkü longlar zaten tüm veritabanı dizileriyle
uyumludur, en yaygın kimlik veri tipidir ve tüm ortak kullanım senaryolarını karşılayabilecek uzunluktadır.

Aşağıdaki kod parçası, bir Acl'nin nasıl oluşturulacağını veya mevcut bir Acl'nin nasıl değiştirileceğini gösterir:

```
// Prepare the information we'd like in our access control entry (ACE)
ObjectIdentity oi = new ObjectIdentityImpl(Foo.class, new Long(44));
Sid sid = new PrincipalSid("Samantha");
Permission p = BasePermission.ADMINISTRATION;

// Create or update the relevant ACL
MutableAcl acl = null;
try {
acl = (MutableAcl) aclService.readAclById(oi);
} catch (NotFoundException nfe) {
acl = aclService.createAcl(oi);
}

// Now grant some permissions via an access control entry (ACE)
acl.insertAce(acl.getEntries().length, p, sid, true);
aclService.updateAcl(acl);
```

Yukarıda ki örnekte, kimlik numarası 44 olan Foo domain nesnesi ile ilişkilendirilmiş ACL'yi alıyoruz. Sonra bir ACE
ekleyerek "Samantha" adlı bir principal'ın nesneyi "administer" yapmasını sağlıyoruz. Kod parçası oldukça açıklayıcıdır,
ancak insertAce metoduna gelince, ilk argüman yeni girişin Acl içinde hangi konuma yerleştirileceğini belirler. Örnekte,
yeni ACE'yi mevcut ACE'lerin sonuna koyduk. Son argüman, ACE'nin granting (izin verme) mi yoksa denying (izin vermeme)
mi olduğunu belirten bir boolean değeridir. Genellikle granting (true) olarak ayarlanır. Ancak, denying (false) ise,
izinler etkili bir şekilde engellenmiş olur.

Spring Security, DAO veya repository işlemlerinin bir parçası olarak ACL'leri otomatik olarak oluşturmak, güncellemek
veya silmek için özel bir entegrasyon sağlamaz. Bunun yerine, örneklerde gösterildiği gibi, kendi domain nesneleriniz
için benzer kodları yazmanız gerekmektedir. ACL bilgilerini servis katmanı işlemlerinizle otomatik olarak entegre etmek
için servis katmanınızda AOP kullanmayı düşünebilirsiniz. Bu yaklaşımın etkili olduğunu gözlemlemiş bulunmaktayız.

Burada açıklanan teknikleri kullanarak veritabanında ACL bilgilerini depoladıktan sonra, bir sonraki adım gerçekten ACL
bilgisini yetkilendirme kararı mantığı olarak kullanmaktır. Burada birkaç seçeneğiniz bulunmaktadır. Kendi
AccessDecisionVoter veya AfterInvocationProvider sınıflarınızı yazabilirsiniz. Bu sınıflar sırasıyla bir yöntem
çağrısından önce veya sonra çalışır. Bu sınıflar, ilgili ACL'yi almak için AclService'yi kullanır ve ardından
Acl.isGranted(Permission[] permission, Sid[] sids, boolean administrativeMode) yöntemini çağırarak iznin verilip
verilmediğine karar verir. Alternatif olarak, AclEntryVoter, AclEntryAfterInvocationProvider veya
AclEntryAfterInvocationCollectionFilteringProvider gibi sınıfları kullanabilirsiniz. Tüm bu sınıflar, çalışma zamanında
ACL bilgilerini değerlendirmek için deklaratif bir yaklaşım sunar ve herhangi bir kod yazmanızı gerektirmez.