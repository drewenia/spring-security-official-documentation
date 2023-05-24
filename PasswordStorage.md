# Storage Mechanism

Kullanıcı adı ve şifre okuma için desteklenen her bir mekanizma, desteklenen depolama mekanizmalarından herhangi birini 
kullanabilir.  Spring Security, çeşitli kimlik bilgisi okuma mekanizmalarını destekler, örneğin HTTP temel kimlik 
doğrulama, form tabanlı kimlik doğrulama, OAuth, JWT ve daha fazlası. Her bir kimlik doğrulama mekanizması, 
kullanıcı adı ve şifre gibi kimlik bilgilerini okumak için farklı yöntemler kullanabilir.

* SimpleStorage with **_In-Memory Authentication_**
* Relational Database with **_JDBC Authentication_**
* Custom data stores with **_UserDetailsService_**
* LDAP storage with **_LDAP Authentication_**

## In-Memory Authentication

Spring Security'nin InMemoryUserDetailsManager'ı, bellekte depolanan kullanıcı adı/şifre tabanlı kimlik doğrulama 
desteği sağlamak için UserDetailsService'i uygular. InMemoryUserDetailsManager, UserDetailsManager interface'ini 
uygulayarak UserDetails'in yönetimini sağlar. UserDetails tabanlı kimlik doğrulama, Spring Security tarafından, 
kimlik doğrulama için bir kullanıcı adı ve parolayı kabul edecek şekilde yapılandırıldığında kullanılır.

Aşağıdaki örnekte kullanılmak üzere Spring CLI'ini kullanarak bir password üretiyorum;

* terminalde **spring encodepassword password** dediğimizde password generate ediliyor

```
@Bean
public UserDetailsService users() {
	UserDetails user = User.builder()
		.username("user")
		.password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
		.roles("USER")
		.build();
	UserDetails admin = User.builder()
		.username("admin")
		.password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
		.roles("USER", "ADMIN")
		.build();
	return new InMemoryUserDetailsManager(user, admin);
}
```
Yukarıda ki örneğin şifreleri güvenli bir şekilde depoladığını ancak kullanıcıların başlangıç deneyiminde bazı 
eksiklikler olduğunu göstemektedir. Şifrelerin güvenli bir şekilde depolanması, genellikle şifreleri düz metin olarak 
saklamamak ve kriptografik yöntemlerle korumak anlamına gelir.

```
@Configuration
public class DefaultSecurityConfig {
    @Bean
    public UserDetailsService users() {
        User.UserBuilder users = User.withDefaultPasswordEncoder();
        UserDetails user = users
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
```
Yukarıda ki örnekte User.withDefaultPasswordEncoder, kullanıcının şifresini bir koddan varsayılan bir şifreleyici 
kullanarak koruyan bir yardımcı yöntemdir. Bu yöntem, bir kullanıcının şifresini düz metin olarak depolamak yerine, 
şifreyi otomatik olarak bir şifreleyiciye geçirir ve güvenli bir formatta saklar.Ancak, kaynak kodun decompile 
yoluyla şifrenin elde edilmesine karşı koruma sağlamaz. Bu durum, güvenlik açısından dikkate alınması gereken bir 
noktadır. Özellikle güvenli bir uygulama geliştirme hedeflendiğinde, şifreleri decompile edilme riskine karşı korumak 
için daha güçlü güvenlik önlemleri düşünülmelidir. Production'da kullanılmaz. withDefaultPasswordEncoder deprecate
edilmiştir. Yerine @Bean seklinde BCryptPasswordEncoder kullanılmalıdır

## JDBC Authentication

Spring Security'nin JdbcDaoImpl sınıfı, JDBC kullanarak alınan kullanıcı adı ve şifre tabanlı kimlik doğrulama desteği 
sağlamak için UserDetailsService interface'ini uygular. UserDetailsService, Spring Security'nin kimlik doğrulama 
sürecinde kullanılan bir arabirimdir. JdbcDaoImpl sınıfı, bu arabirimi uygulayarak, JDBC aracılığıyla kullanıcı adı ve 
şifre bilgilerini alarak kimlik doğrulama sağlar. 

JdbcUserDetailsManager sınıfı, JdbcDaoImpl sınıfından extend edilmişti, bu da onun JDBC ile kullanıcı ayrıntılarının 
saklanmasını ve yönetimini sağlayan yeteneklere sahip olduğunu gösterir. Bu sınıf, kullanıcı ayrıntılarının eklenmesi, 
güncellenmesi, silinmesi, sorgulanması gibi işlemleri gerçekleştirmek için JDBC'yi kullanır.

UserDetails-based authentication, Spring Security'nin kullanıcı kimlik doğrulama sürecinde kullanılan bir yöntemdir. 
Bu yöntemde, kimlik doğrulama için kullanıcı adı ve şifre çifti kabul edilir. Spring Security, bu kullanıcı adı ve 
şifreyi alarak UserDetails nesnesini oluşturur.

- Default Schema

JDBC tabanlı kimlik doğrulama kullanıldığında, kullanıcıların kimlik bilgileri veritabanında depolanır ve
Spring Security bu bilgilere erişmek için SQL sorgularını kullanır. Spring Security, kullanıcı adı/şifre tabanlı
kimlik doğrulama için bazı varsayılan sorguları sağlar. Spring Security'nin varsayılan sorguları, genellikle
UserDetailsService ile birleştirilerek veya UserDetailsManager üzerinden yapılandırılarak kullanılır. Bu sorgular,
JDBC üzerinden veritabanına erişerek kimlik doğrulama işlemlerini gerçekleştirir.

- User Schema

JdbcDaoImpl, UserDetails tabanlı kimlik doğrulaması için kullanılan bir sınıftır ve JDBC tabanlı kimlik doğrulama 
işlemlerini gerçekleştirir. Bu işlemler için JdbcDaoImpl, kullanıcının kimlik bilgilerini doğrulamak ve kullanıcının 
yetkilerini yüklemek için belirli tablolara ihtiyaç duyar.

Classpath, bir Java projesinin çalışma zamanında kullanılan kaynak dosyalarını ve sınıfları içeren bir yol dizinidir. 
Varsayılan şema dosyası, projenin classpath'ine dahil edilir ve adıyla erişilebilir hale getirilir. Genellikle, 
varsayılan şema dosyasının adı "schema.sql" veya "database.sql" gibi bir şeydir. Bu dosya, kullanıcı bilgilerini 
depolamak için gereken tabloları oluşturmak için gerekli SQL ifadelerini içerir.

External Libraries içerisinde: org/springframework/security/core/userdetails/jdbc/users.ddl isimli DefaultUserSchema'sı
bulunur

- Group Schema

Eğer uygulamanız group'ları kullanıyorsa group schema'yı sağlamanız gerekmektedir. Aşağıdaki örnek;
```
create table groups (
	id bigint generated by default as identity(start with 0) primary key,
	group_name varchar_ignorecase(50) not null
);

create table group_authorities (
	group_id bigint not null,
	authority varchar(50) not null,
	constraint fk_group_authorities_group foreign key(group_id) references groups(id)
);

create table group_members (
	id bigint generated by default as identity(start with 0) primary key,
	username varchar(50) not null,
	group_id bigint not null,
	constraint fk_group_members_group foreign key(group_id) references groups(id)
);
```

- Setting up a MySQL Database
Docker uzerinden mysql container'i create ediyorum. Test adında bir DB yaratıyorum ve icerisine asagidaki MYSQL
sorgusunu calistiyorum
```
create table users
(
    username varchar(50)  not null primary key,
    password varchar(500) not null,
    enabled  boolean      not null
);
create table authorities
(
    username  varchar(50) not null,
    authority varchar(50) not null,
    constraint fk_authorities_users foreign key (username) references users (username)
);
create unique index ix_auth_username on authorities (username, authority);
```
- Setting up a DataSource
JdbcUserDetailsManager'i yapılandırmadan önce bir DataSource oluşturmalıyız.
```
@Bean
    public DataSource dataSource() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/test");
        dataSource.setUsername("root");
        dataSource.setPassword("verysecretpass");
        return dataSource;
    }
```

- JdbcUserDetailsManager Bean.Spring CLI ile sifre generate ediyoruz.
```
@Bean
    UserDetailsManager users(DataSource dataSource) {
        UserDetails user = User.builder()
                .username("user")
                .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
                .roles("USER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
                .roles("ADMIN")
                .build();
        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
        users.createUser(user);
        users.createUser(admin);
        return users;
    }
```
Yukarıda ki Bean yardımıyla DB'ye user ve admin object'leri otomatik olarak insert ediliyor

## UserDetails
UserDetails, UserDetailsService tarafından döndürülür. DaoAuthenticationProvider, UserDetails'ı doğrular ve ardından 
yapılandırılmış UserDetailsService tarafından döndürülen UserDetails'ı içeren bir principal'e sahip olan bir 
Authentication nesnesini döndürür. Bu ifade, kullanıcı ayrıntılarının UserDetails nesnesi olarak temsil edildiği ve bu 
ayrıntıların UserDetailsService tarafından sağlandığından bahsetmektedir. UserDetails, bir kullanıcının kimlik 
bilgilerini (kullanıcı adı, şifre, roller vb.) içeren bir interface'i temsil eder. UserDetailsService, kullanıcı 
ayrıntılarını sağlamak için kullanılan bir arayüzdür. Bu arayüzü uygulayan sınıflar, kullanıcı verilerini bir 
veritabanından, bir API'den veya başka bir kaynaktan alabilir. UserDetailsService, genellikle kimlik doğrulama 
işlemi sırasında kullanıcının ayrıntılarını almak için kullanılır. DaoAuthenticationProvider, UserDetails'ı doğrulamak 
ve kimlik doğrulama işlemi için bir Authentication nesnesi oluşturmakla sorumludur. Bu işlem genellikle kullanıcının 
sağladığı kimlik bilgilerini (kullanıcı adı ve şifre gibi) kullanarak UserDetails nesnesinin doğrulanmasını içerir.

Sonuç olarak, DaoAuthenticationProvider, UserDetails'ı doğrular ve ardından bu doğrulanmış kullanıcı ayrıntılarını 
içeren bir Authentication nesnesi oluşturur. Bu Authentication nesnesi, kullanıcının kimlik doğrulama sürecini 
geçtiğini ve yetkilendirme ve diğer güvenlik kontrolleri için kullanılabileceğini temsil eder.

## UserDetailsService
UserDetailsService, DaoAuthenticationProvider tarafından kullanılır ve bir kullanıcı adı, şifre ve diğer öznitelikleri 
almak için kullanılır. Bir kullanıcı adı ve şifre ile kimlik doğrulama yapmak için kullanılır.

UserDetailsService, genellikle kimlik doğrulama işlemi sırasında kullanıcının kimlik bilgilerini almak için kullanılır. 
İstemciden gelen kimlik bilgileri, kullanıcı adı ve şifre gibi, UserDetailsService aracılığıyla alınır.

Spring Security, UserDetailsService için in-memory ve JDBC tabanlı implementasyonlar sağlar.
* In-Memory UserDetailsService: Bu implementasyon, kullanıcı ayrıntılarını bellekte bir veri yapısında 
(genellikle bir Map) saklar. Örneğin, kullanıcı adları, şifreler ve roller gibi bilgileri içeren bir Map 
kullanılabilir. Bu yöntem basit uygulamalar için uygundur, ancak büyük kullanıcı tabanları veya güncellemeler 
gerektiren senaryolarda kullanışsız olabilir.
* JDBC UserDetailsService: Bu implementasyon, kullanıcı ayrıntılarını bir JDBC veritabanından alır. 
JDBC UserDetailsService, genellikle kullanıcı bilgilerinin bir veritabanında saklandığı ve kimlik doğrulama işlemi 
sırasında bu veritabanının kullanıldığı durumlarda tercih edilir. Veritabanında kullanıcı tablosu ve gerekli sütunlar 
(kullanıcı adı, şifre, roller vb.) bulunmalıdır. Bu şekilde, kullanıcı kimlik bilgileri güvenli bir şekilde 
saklanabilir ve veritabanı kullanıcı yönetimi sağlanabilir.

Özelleştirilmiş kimlik doğrulama yapmak için, özel bir UserDetailsService uygulamasını bir bean olarak açığa 
çıkarabilirsiniz. Aşağıdaki örnek, CustomUserDetailsService sınıfının UserDetailsService arayüzünü uyguladığını 
varsayarak kimlik doğrulamayı özelleştiriyor.

Örneğin;
UserDetailsService arayüzünü uygulayan CustomUserDetailsService adında bir sınıf oluşturun. Bu sınıf, kimlik doğrulama 
süreci sırasında kullanıcıya özgü verileri yüklemekten sorumlu olacak.

```
public class CustomUserDetailsService implements UserDetailsService {
    // Implement the loadUserByUsername method to load user-specific data based on the provided username
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Custom logic to load user details from a data source
        // Return an instance of UserDetails that represents the user
    }
}
```
Bu sınıfı Spring container'ina bir bean olarak ekleyin. Bunun için, @Service, @Component veya @Bean gibi bir Spring 
bileşeni anotasyonunu kullanabilirsiniz. Spring Security konfigürasyonunda, bu özelleştirilmiş UserDetailsService'ı 
kullanarak kimlik doğrulama işlemini yapılandırabilirsiniz.

```
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }
    
    // ...
}
```

## PasswordEncoder

Elbette! Spring Security'nin servlet desteği, PasswordEncoder ile entegre olarak şifreleri güvenli bir şekilde 
depolamayı içerir. PasswordEncoder, şifreleri kodlamak ve doğrulamakla sorumludur. Spring Security tarafından 
kullanılan PasswordEncoder uygulamasını özelleştirmek için, bir PasswordEncoder bean'ini açığa çıkarmanız 
gerekmektedir. Bu şekilde, Spring Security, belirtilen PasswordEncoder bean'ini kullanarak şifreleri kodlama ve 
doğrulama işlemlerini gerçekleştirecektir. Bu, şifrelerin güvenli bir şekilde depolanmasını sağlamak için kullanılan 
algoritmayı ve yapılandırmaları belirlemenize olanak tanır. Özelleştirilmiş bir PasswordEncoder bean'ini açığa çıkarmak
için aşağıdaki gibi bir yapılandırma yapabilirsiniz:

```
@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Return your custom PasswordEncoder implementation
        // Example: return new BCryptPasswordEncoder();
    }

    // Other security configuration...
}
```
Bu örnekte, passwordEncoder() adında bir PasswordEncoder bean'i tanımlanmıştır. Kendi özel PasswordEncoder 
uygulamanızı döndürmelisiniz. Örneğin, BCryptPasswordEncoder kullanarak şifreleri kodlamak için 
new BCryptPasswordEncoder() ifadesini döndürebilirsiniz. Böylece, özelleştirilmiş PasswordEncoder uygulamanızı 
Spring Security ile entegre edebilir ve şifreleri güvenli bir şekilde depolayabilirsiniz.

## DaoAuthenticationProvider

DaoAuthenticationProvider bir AuthenticationProvider implementasyonudur ve bir UserDetailsService ve PasswordEncoder 
kullanarak bir kullanıcı adı ve şifresini doğrulamak için kullanılır. DaoAuthenticationProvider'ın temel işlevi, 
kullanıcının sağladığı kimlik bilgilerini (kullanıcı adı ve şifre) kullanarak bir doğrulama işlemi gerçekleştirmektir. 
Bu işlem sırasında, UserDetailsService kullanıcı ayrıntılarını alır ve doğru kullanıcı bulunduğunda PasswordEncoder 
kullanıcı tarafından sağlanan şifreyi doğrular. Bu şekilde, DaoAuthenticationProvider kullanarak bir kullanıcının 
kimlik doğrulamasını gerçekleştirebilirsiniz. Bu, veritabanından kullanıcı bilgilerini almak ve doğru şifreleme 
algoritmasını kullanarak şifreleri doğrulamak için yaygın olarak kullanılan bir yöntemdir.

![img.png](img.png)

1 - "Reading the Username & Password" bölümündeki authentication Filter'i, isteğin içerisinden kullanıcı adını ve şifreyi 
çıkarmak ve bir UsernamePasswordAuthenticationToken nesnesi oluşturmakla görevlidir. Bu token, kullanıcının kimlik 
bilgilerini temsil eder ve sonra AuthenticationManager'a iletilir.

2 - AuthenticationManager, Spring Security tarafından sağlanan bir arayüzdür ve kimlik doğrulama işlemlerini yönetir. 
ProviderManager, AuthenticationManager arayüzünü uygulayan bir örnektir. AuthenticationManager, gelen kimlik doğrulama 
isteğini alır ve doğrulama işlemini gerçekleştirmek için ilgili kimlik doğrulayıcıları (AuthenticationProvider) 
kullanır. ProviderManager, kimlik doğrulama işlemini yöneten ve AuthenticationManager arayüzünü uygulayan bir sınıftır. 
DaoAuthenticationProvider türünde bir AuthenticationProvider kullanarak yapılandırılan ProviderManager, kimlik 
doğrulama işlemini gerçekleştirmek için bu özel AuthenticationProvider'ı kullanır.

3 - DaoAuthenticationProvider UserDetailsService'den UserDetails'i arar

4 - DaoAuthenticationProvider, önceki adımda döndürülen UserDetails üzerindeki parolayı doğrulamak için 
PasswordEncoder'ı kullanır.

5 - Kimlik doğrulama başarılı olduğunda, döndürülen Authentication nesnesi UsernamePasswordAuthenticationToken 
türündedir ve principal (anahtar) olarak, yapılandırılmış UserDetailsService tarafından döndürülen UserDetails 
nesnesini içerir. Sonuç olarak, döndürülen UsernamePasswordAuthenticationToken, kimlik doğrulama Filtresi tarafından 
SecurityContextHolder üzerine ayarlanır.