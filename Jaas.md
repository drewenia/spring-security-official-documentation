# Java Authentication and Authorization Service (JAAS) Provider

Spring Security, Java Authentication and Authorization Service (JAAS) taleplerini işlemek için bir paket sağlar. Bu
bölümde bu paket ele alınacaktır

Spring Security, JAAS ile entegrasyonu sağlamak için org.springframework.security.authentication.jaas paketini içerir.
Bu paket, Spring Security'nin JAAS'ya kimlik doğrulama taleplerini yönlendirmesini ve sonuçta elde edilen kimlik
doğrulama bilgilerini işlemesini sağlayan sınıf ve arabirimleri içerir.

## AbstractJaasAuthenticationProvider

AbstractJaasAuthenticationProvider sınıfı, sağlanan JAAS AuthenticationProvider uygulamaları için temel işlevi sağlar.
Alt sınıfların LoginContext'i oluşturan bir yöntemi uygulaması gerekmektedir. AbstractJaasAuthenticationProvider,
enjekte edilebilecek bir dizi bağımlılığa sahiptir ve bu bölümde tartışılmaktadır.

AbstractJaasAuthenticationProvider sınıfının bazı önemli bağımlılıkları şunlardır:
1 - JaasAuthenticationCallbackHandler: Bu callback işleyicisi, JAAS kimlik doğrulama işlemini gerçekleştirmekten
sorumludur. JAAS konfigürasyonunda kullanılan callback işleyicisi özelleştirilebilir.

2 - JaasAuthenticationProvider: Bu sağlayıcı, JAAS kimlik doğrulama işlemi için LoginContext'i oluşturur ve kullanıcıyı
doğrular. Ayrıca, kullanıcıya atanan yetkileri bildirir.

3 - JaasAuthoritiesPopulator: Bu popülatör, kimlik doğrulama işleminden sonra kullanıcının yetkilerini doldurur. JAAS
kimlik doğrulama sonrası yetki ataması yapmak için kullanılabilir.

### JAAS CallbackHandler

Çoğu JAAS LoginModule örneği, bir callback gerektirir. Bu callback genellikle kullanıcıdan kullanıcı
adı ve parola gibi bilgileri almak için kullanılır.

Spring Security dağıtımında, kullanıcı etkileşimi Spring Security tarafından yönetilir (kimlik doğrulama mekanizması
aracılığıyla). Bu nedenle, kimlik doğrulama isteği JAAS'a iletilirken, Spring Security'nin kimlik doğrulama mekanizması
tarafından tamamen doldurulmuş bir Authentication nesnesi bulunur. Bu Authentication nesnesi, JAAS LoginModule
tarafından gereken tüm bilgileri içerir.

Spring Security için JAAS paketi, iki varsayılan callback handler sağlar:
JaasNameCallbackHandler ve JaasPasswordCallbackHandler. Her biri JaasAuthenticationCallbackHandler'ı uygular. Bu
callback handler'lar çoğu durumda, iç mekanizmaları anlamadan kullanılabilir.

Callback davranışını tam kontrol altına almak isteyenler için AbstractJaasAuthenticationProvider, bu
JaasAuthenticationCallbackHandler örneklerini InternalCallbackHandler ile wrap eder. InternalCallbackHandler sınıfı,
JAAS'ın normal CallbackHandler arabirimini uygulayan sınıftır. Bu sınıf, JAAS LoginModule tarafından gereken callback
işlemlerini yönetmekten sorumludur. Herhangi bir JAAS LoginModule kullanıldığında, yapılandırılmış
InternalCallbackHandler örneklerinden oluşan bir uygulama bağlamı listesi geçirilir. Bu bağlamlar, JAAS LoginModule'un
callback işlemlerini yönetmek için kullanacağı InternalCallbackHandler örneklerini sağlar. Örneğin, kullanıcı adı ve
parola callback işlemlerini yönetmek için bir JaasNameCallbackHandler ve JaasPasswordCallbackHandler örneği
geçirilebilir. Bu şekilde, JAAS LoginModule, belirtilen SecurityContext'e erişerek gerekli callback işlemlerini
yapabilir.Eğer LoginModule, InternalCallbackHandler örneklerine callback yapılmasını istiyorsa, bu callback sırasıyla
wrap edilen JaasAuthenticationCallbackHandler örneklerine iletilir. Bu sayede, JAAS LoginModule, callback işlemlerini
yönetmek için belirtilen JaasAuthenticationCallbackHandler örneklerini kullanabilir.

### JAAS AuthorityGranter

JAAS çalışma prensibiyle uyumlu olarak, roller dâhil tüm "principal" (özne) kavramları JAAS tarafından kullanılır. Diğer
yandan, Spring Security, Authentication nesneleri üzerinde çalışır. Her Authentication nesnesi, tek bir principal (özne)
ve birden fazla GrantedAuthority (verilmiş yetki) örneği içerir. Bu farklı kavramlar arasında eşleme yapmayı
kolaylaştırmak için Spring Security'nin JAAS paketi, AuthorityGranter arayüzünü içerir.

An AuthorityGranter, JAAS bir principal'i inceleyerek principal'a atanan yetkileri temsil eden bir dizi String nesnesini
döndürmekten sorumludur. Her döndürülen authority string, AbstractJaasAuthenticationProvider, AuthorityGranter'a
geçirilen JAAS öznesini içeren bir JaasGrantedAuthority (Spring Security'nin GrantedAuthority arayüzünü uygular)
oluşturur. AbstractJaasAuthenticationProvider, önce JAAS LoginModule kullanarak kullanıcının kimlik bilgilerini
başarıyla doğrulayarak ve ardından döndürdüğü LoginContext'e erişerek JAAS principal'larını elde eder.

AbstractJaasAuthenticationProvider tarafından LoginContext.getSubject().getPrincipals() çağrısı yapılır ve elde edilen
her bir principal, AbstractJaasAuthenticationProvider.setAuthorityGranters(List) özelliği ile tanımlanan her
AuthorityGranter'a aktarılır. Spring Security, her bir JAAS principal'in uygulama özelinde anlam ifade ettiği göz önüne
alındığında, herhangi bir üretim AuthorityGranter örneği içermez. Bununla birlikte, birim testlerde basit bir
AuthorityGranter uygulamasını gösteren TestAuthorityGranter bulunmaktadır.

## DefaultJaasAuthenticationProvider

DefaultJaasAuthenticationProvider, JAAS Configuration nesnesini bir bağımlılık olarak enjekte etmeye izin verir. Enjekte
edilen JAAS Configuration kullanılarak bir LoginContext oluşturur. JaasAuthenticationProvider'ın aksine,
DefaultJaasAuthenticationProvider belirli bir Configuration uygulamasına bağlı değildir.

### InMemory Configuration

DefaultJaasAuthenticationProvider'a bir Configuration enjekte etmeyi kolaylaştırmak için InMemoryConfiguration adında
bir varsayılan in-memory implementasyon sağlanmıştır. InMemoryConfiguration uygulaması bir Map'i kabul eden bir
constructor'a sahiptir. Her bir key, bir login configuration name'i temsil ederken, value ise AppConfigurationEntry
instance'larının bir dizisini temsil eder. InMemoryConfiguration, sağlanan Map içinde bir eşleme bulunmadığında
kullanılan varsayılan AppConfigurationEntry nesnelerinin bir dizisini de destekler.

### DefaultJaasAuthenticationProvider Example Configuration

InMemoryConfiguration, Standart JAAS yapılandırma dosyalarına göre Spring yapılandırması daha ayrıntılı olabilir. Ancak,
DefaultJaasAuthenticationProvider ile birlikte kullanmak, varsayılan Configuration uygulamasına bağımlı olmadığı için
JaasAuthenticationProvider'dan daha esnek bir yapı sağlar. Aşağıdaki örnek, InMemoryConfiguration kullanan
DefaultJaasAuthenticationProvider'ın yapılandırmasını sağlar. Unutmayın ki, özel Configuration uygulamaları da
kolaylıkla DefaultJaasAuthenticationProvider'a enjekte edilebilir XML:

```
<bean id="jaasAuthProvider"
class="org.springframework.security.authentication.jaas.DefaultJaasAuthenticationProvider">
<property name="configuration">
<bean class="org.springframework.security.authentication.jaas.memory.InMemoryConfiguration">
<constructor-arg>
	<map>
	<!--
	SPRINGSECURITY is the default loginContextName
	for AbstractJaasAuthenticationProvider
	-->
	<entry key="SPRINGSECURITY">
	<array>
	<bean class="javax.security.auth.login.AppConfigurationEntry">
		<constructor-arg value="sample.SampleLoginModule" />
		<constructor-arg>
		<util:constant static-field=
			"javax.security.auth.login.AppConfigurationEntry$LoginModuleControlFlag.REQUIRED"/>
		</constructor-arg>
		<constructor-arg>
		<map></map>
		</constructor-arg>
		</bean>
	</array>
	</entry>
	</map>
	</constructor-arg>
</bean>
</property>
<property name="authorityGranters">
<list>
	<!-- You will need to write your own implementation of AuthorityGranter -->
	<bean class="org.springframework.security.authentication.jaas.TestAuthorityGranter"/>
</list>
</property>
</bean>
```

JAVA :

```
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // Other configurations...
            .authenticationProvider(defaultJaasAuthenticationProvider());
    }

    @Bean
    public DefaultJaasAuthenticationProvider defaultJaasAuthenticationProvider() {
        DefaultJaasAuthenticationProvider authenticationProvider = new DefaultJaasAuthenticationProvider();
        authenticationProvider.setConfiguration(inMemoryConfiguration());
        return authenticationProvider;
    }

    @Bean
    public InMemoryConfiguration inMemoryConfiguration() {
        Map<String, AppConfigurationEntry[]> configMap = new HashMap<>();
        // Configure your login configuration entries here
        // For example:
        AppConfigurationEntry[] configEntries = new AppConfigurationEntry[]{
                new AppConfigurationEntry("com.example.LoginModule", AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap<>())
        };
        configMap.put("default", configEntries);
        
        return new InMemoryConfiguration(configMap);
    }
}

```

Yukarıdaki yapılandırmada, DefaultJaasAuthenticationProvider örneği oluşturulurken InMemoryConfiguration kullanılır.
inMemoryConfiguration() yöntemi, örnek bir InMemoryConfiguration nesnesi oluşturur ve gerekli login yapılandırma
girişlerini map olarak tanımlar. Burada kendi login yapılandırma girişlerinizi yapılandırabilirsiniz.

## JaasAuthenticationProvider

JaasAuthenticationProvider, varsayılan Configuration'ın ConfigFile bir örneği olduğunu varsayar. Bu varsayım,
Configuration'ı güncellemeyi denemek için yapılır. Ardından JaasAuthenticationProvider, LoginContext'i oluşturmak için
varsayılan Configuration'ı kullanır.

ConfigFile, bir JAAS Configuration uygulamasıdır ve JAAS yapılandırmasını bir dosyadan okur. Varsayılan olarak, dosyanın
adı "jaas.config" olarak beklenir ve sınıf yolu kökünde bulunur. Bununla birlikte, isteğe bağlı olarak farklı bir konum
için "java.security.auth.login.config" sistem özelliğini istenen dosya yoluyla ayarlayabilirsiniz.

Aşağıda, varsayılan ConfigFile'u kullanan JaasAuthenticationProvider için bir yapılandırma örneği verilmiştir:

```
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // Diğer yapılandırmalar...
            .authenticationProvider(jaasAuthenticationProvider());
    }

    @Bean
    public JaasAuthenticationProvider jaasAuthenticationProvider() {
        JaasAuthenticationProvider authenticationProvider = new JaasAuthenticationProvider();
        authenticationProvider.setLoginConfig("classpath:jaas.config");
        authenticationProvider.setLoginContextName("myLoginContext");
        return authenticationProvider;
    }
}
```

Yukarıdaki örnekte, jaasAuthenticationProvider() bean'i JaasAuthenticationProvider'nın bir örneğini oluşturur ve JAAS
yapılandırma dosyasının konumunu (jaas.config) ve LoginContext'in adını (myLoginContext) yapılandırır. Bu değerleri
kendi özel yapılandırmanıza göre ayarlayabilirsiniz.

Aşağıdaki içeriğe sahip /WEB-INF/login.conf adlı bir JAAS oturum açma yapılandırma dosyamız olduğunu varsayalım TXT:

```
JAASTest {
	sample.SampleLoginModule required;
};
```

Aslında, Spring Security'nin tüm bean'leri gibi, JaasAuthenticationProvider da application context üzerinden
yapılandırılır. Aşağıdaki tanımlamalar, yukarıdaki JAAS giriş yapılandırma dosyasına karşılık gelir XML:

```
<bean id="jaasAuthenticationProvider"
class="org.springframework.security.authentication.jaas.JaasAuthenticationProvider">
<property name="loginConfig" value="/WEB-INF/login.conf"/>
<property name="loginContextName" value="JAASTest"/>
<property name="callbackHandlers">
<list>
<bean
	class="org.springframework.security.authentication.jaas.JaasNameCallbackHandler"/>
<bean
	class="org.springframework.security.authentication.jaas.JaasPasswordCallbackHandler"/>
</list>
</property>
<property name="authorityGranters">
	<list>
	<bean class="org.springframework.security.authentication.jaas.TestAuthorityGranter"/>
	</list>
</property>
</bean>
```

## Running as a Subject

Eğer yapılandırıldıysa, JaasApiIntegrationFilter, JaasAuthenticationToken üzerinde kimlik doğrulamasını gerçekleştiren
Subject olarak çalışmaya çalışır. Bu durumda, doğrulanmış subject'e aşağıdaki şekilde erişebilirsiniz:

```
Subject subject = Subject.getSubject(AccessController.getContext());
```

JaasApiIntegrationFilter'i yapılandırmak için jaas-api-provision attribute'unu kullanabilirsiniz. Bu özellik, JAAS
Subject'in dolu olmasına dayanan eski veya harici API'lerle entegre olurken faydalı olabilir.