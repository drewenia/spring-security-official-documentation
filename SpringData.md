# Spring Data Integration

Spring Security, Spring Data entegrasyonu sağlar ve sorgularınız içinde mevcut kullanıcıya başvurmanıza olanak tanır.
Sonuçları sonradan filtrelemek yerine sonuçlara kullanıcıyı dahil etmek, sayfalı sonuçları desteklemek için sadece
yararlı değil, aynı zamanda gereklidir çünkü sonradan filtreleme ölçeklendirilemez.

## Spring Data & Spring Security Configuration

Bu desteği kullanmak için, org.springframework.security:spring-security-data bağımlılığını ekleyin ve
SecurityEvaluationContextExtension türünde bir bean sağlayın.

```
@Bean
public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
	return new SecurityEvaluationContextExtension();
}
```

XML Yapılandırmasında bu şöyle görünür: (XML)

```
<bean class="org.springframework.security.data.repository.query.SecurityEvaluationContextExtension"/>
```

## Security Expressions within @Query

Artık sorgularınızda Spring Security'yi kullanabilirsiniz:

```
@Repository
public interface MessageRepository extends PagingAndSortingRepository<Message,Long> {
	@Query("select m from Message m where m.to.id = ?#{ principal?.id }")
	Page<Message> findInbox(Pageable pageable);
}
```

Bu, Authentication.getPrincipal().getId() değerinin Message'ın alıcısıyla eşit olup olmadığını kontrol eder. Bu örnek,
temel nesnesini bir id özelliğine sahip bir nesne olarak özelleştirdiğinizi varsayar. SecurityEvaluationContextExtension
bean'ini kullanılabilir hale getirerek, Sorgu içinde tüm Common Security Expressions'ları kullanılabilir hale gelir.