# Authorization Events

Her reddedilen yetkilendirme için bir AuthorizationDeniedEvent olayı tetiklenir. Ayrıca, verilen yetkilendirmeler için
AuthorizationGrantedEvent olayını tetiklemek de mümkündür. Bu olayları dinlemek için öncelikle bir
AuthorizationEventPublisher yayınlamanız gerekir.

Spring Security'nin SpringAuthorizationEventPublisher'ı genellikle yeterli olacaktır. Bu, Spring'in
ApplicationEventPublisher'ını kullanarak yetkilendirme olaylarını yayınlar:

```
@Bean
public AuthorizationEventPublisher authorizationEventPublisher
        (ApplicationEventPublisher applicationEventPublisher) {
    return new SpringAuthorizationEventPublisher(applicationEventPublisher);
}
```

Ardından, Spring'in @EventListener desteğini kullanabilirsiniz:

```
@Component
public class AuthenticationEvents {

    @EventListener
    public void onFailure(AuthorizationDeniedEvent failure) {
		// ...
    }
}
```

## Authorization Granted Events

AuthorizationGrantedEvents oldukça gürültülü olma potansiyeline sahip olduğundan, varsayılan olarak yayınlanmazlar.
Aslında, bu olayları yayınlamak, uygulamanızın gürültülü yetkilendirme olaylarıyla dolup taşmamasını sağlamak için
muhtemelen sizin açınızdan bazı business logic'leri gerektirecektir

Belirli bir kriter temelinde başarılı event'leri filtreleyen kendi event publisher'ınızı oluşturmanıza yardımcı
olabilirim. Bu durumda, publisher yalnızca "ROLE_ADMIN" rolünün required olduğu yetkilendirme onaylarını publish eder.

```
@Component
public class MyAuthorizationEventPublisher implements AuthorizationEventPublisher {
    private final ApplicationEventPublisher publisher;
    private final AuthorizationEventPublisher delegate;

    public MyAuthorizationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
        this.delegate = new SpringAuthorizationEventPublisher(publisher);
    }

    @Override
    public <T> void publishAuthorizationEvent(Supplier<Authentication> authentication,
            T object, AuthorizationDecision decision) {
        if (decision == null) {
            return;
        }
        if (!decision.isGranted()) {
            this.delegate.publishAuthorizationEvent(authentication, object, decision);
            return;
        }
        if (shouldThisEventBePublished(decision)) {
            AuthorizationGrantedEvent granted = new AuthorizationGrantedEvent(
                    authentication, object, decision);
            this.publisher.publishEvent(granted);
        }
    }

    private boolean shouldThisEventBePublished(AuthorizationDecision decision) {
        if (!(decision instanceof AuthorityAuthorizationDecision)) {
            return false;
        }
        Collection<GrantedAuthority> authorities = ((AuthorityAuthorizationDecision) decision).getAuthorities();
        for (GrantedAuthority authority : authorities) {
            if ("ROLE_ADMIN".equals(authority.getAuthority())) {
                return true;
            }
        }
        return false;
    }
}
```