# Observability

Spring Security, izleme için Spring Observability ile out of the box entegrasyona sahiptir; ancak ölçüm toplamak için
yapılandırsı da oldukça basittir.

## Tracing

Bir ObservationRegistry bean'i mevcutsa, Spring Security aşağıdaki durumlar için traces (izlemeler) oluşturur:

- the filter chain
- the AuthenticationManager, and
- the AuthorizationManager

### Boot Integration

Örneğin, basit bir Spring Boot uygulamasını düşünelim:

```
@SpringBootApplication
public class MyApplication {
	@Bean
	public UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withDefaultPasswordEncoder()
						.username("user")
						.password("password")
						.authorities("app")
						.build()
		);
	}

	@Bean
	ObservationRegistryCustomizer<ObservationRegistry> addTextHandler() {
		return (registry) -> registry.observationConfig().observationHandler(new ObservationTextHandler());
	}

	public static void main(String[] args) {
		SpringApplication.run(ListenerSamplesApplication.class, args);
	}
}
```

Ve ilgili bir istek:

```
?> http -a user:password :8080
```

Yukarıdaki örnekteki çıktı aşağıdaki gibi olacaktır:

```
START - name='http.server.requests', contextualName='null', error='null', lowCardinalityKeyValues=[], highCardinalityKeyValues=[], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@687e16d1', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=0.001779024, duration(nanos)=1779024.0, startTimeNanos=91695917264958}']
	START - name='spring.security.http.chains', contextualName='spring.security.http.chains.before', error='null', lowCardinalityKeyValues=[chain.position='0', chain.size='17', filter.section='before'], highCardinalityKeyValues=[request.line='GET /'], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@79f554a5', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=7.42147E-4, duration(nanos)=742147.0, startTimeNanos=91695947182029}']
	... skipped for brevity ...
	STOP - name='spring.security.http.chains', contextualName='spring.security.http.chains.before', error='null', lowCardinalityKeyValues=[chain.position='0', chain.size='17', filter.section='before'], highCardinalityKeyValues=[request.line='GET /'], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@79f554a5', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=0.014771848, duration(nanos)=1.4771848E7, startTimeNanos=91695947182029}']
		START - name='spring.security.authentications', contextualName='null', error='null', lowCardinalityKeyValues=[authentication.failure.type='Optional', authentication.method='ProviderManager', authentication.request.type='UsernamePasswordAuthenticationToken'], highCardinalityKeyValues=[], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@4d4b2b56', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=7.09759E-4, duration(nanos)=709759.0, startTimeNanos=91696094477504}']
		... skipped for brevity ...
		STOP - name='spring.security.authentications', contextualName='null', error='null', lowCardinalityKeyValues=[authentication.failure.type='Optional', authentication.method='ProviderManager', authentication.request.type='UsernamePasswordAuthenticationToken', authentication.result.type='UsernamePasswordAuthenticationToken'], highCardinalityKeyValues=[], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@4d4b2b56', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=0.895141386, duration(nanos)=8.95141386E8, startTimeNanos=91696094477504}']
		START - name='spring.security.authorizations', contextualName='null', error='null', lowCardinalityKeyValues=[object.type='Servlet3SecurityContextHolderAwareRequestWrapper'], highCardinalityKeyValues=[], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@6d834cc7', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=3.0965E-4, duration(nanos)=309650.0, startTimeNanos=91697034893983}']
		... skipped for brevity ...
		STOP - name='spring.security.authorizations', contextualName='null', error='null', lowCardinalityKeyValues=[authorization.decision='true', object.type='Servlet3SecurityContextHolderAwareRequestWrapper'], highCardinalityKeyValues=[authentication.authorities='[app]', authorization.decision.details='AuthorizationDecision [granted=true]'], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@6d834cc7', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=0.02084809, duration(nanos)=2.084809E7, startTimeNanos=91697034893983}']
		START - name='spring.security.http.secured.requests', contextualName='null', error='null', lowCardinalityKeyValues=[], highCardinalityKeyValues=[], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@649c5ec3', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=2.67878E-4, duration(nanos)=267878.0, startTimeNanos=91697059819304}']
		... skipped for brevity ...
		STOP - name='spring.security.http.secured.requests', contextualName='null', error='null', lowCardinalityKeyValues=[], highCardinalityKeyValues=[], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@649c5ec3', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=0.090753322, duration(nanos)=9.0753322E7, startTimeNanos=91697059819304}']
	START - name='spring.security.http.chains', contextualName='spring.security.http.chains.after', error='null', lowCardinalityKeyValues=[chain.position='0', chain.size='17', filter.section='after'], highCardinalityKeyValues=[request.line='GET /'], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@47af8207', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=5.31832E-4, duration(nanos)=531832.0, startTimeNanos=91697152857268}']
	... skipped for brevity ...
	STOP - name='spring.security.http.chains', contextualName='spring.security.http.chains.after', error='null', lowCardinalityKeyValues=[chain.position='17', chain.size='17', current.filter.name='DisableEncodeUrlFilter', filter.section='after'], highCardinalityKeyValues=[request.line='GET /'], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@47af8207', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=0.007689382, duration(nanos)=7689382.0, startTimeNanos=91697152857268}']
STOP - name='http.server.requests', contextualName='null', error='null', lowCardinalityKeyValues=[], highCardinalityKeyValues=[request.line='GET /'], map=[class io.micrometer.core.instrument.Timer$Sample='io.micrometer.core.instrument.Timer$Sample@687e16d1', class io.micrometer.core.instrument.LongTaskTimer$Sample='SampleImpl{duration(seconds)=1.245858319, duration(nanos)=1.245858319E9, startTimeNanos=91695917264958}']
```

### Manual Configuration

Spring Boot dışında bir uygulama için veya mevcut Boot yapılandırmasını geçersiz kılmak için kendi ObservationRegistry
nesnenizi yayımlayabilirsiniz ve Spring Security bunu hala algılayacaktır.

```
@SpringBootApplication
public class MyApplication {
	@Bean
	public UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withDefaultPasswordEncoder()
						.username("user")
						.password("password")
						.authorities("app")
						.build()
		);
	}

	@Bean
	ObservationRegistry<ObservationRegistry> observationRegistry() {
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(new ObservationTextHandler());
		return registry;
	}

	public static void main(String[] args) {
		SpringApplication.run(ListenerSamplesApplication.class, args);
	}
}
```

- Disabling Observability

Spring Boot uygulamasında herhangi bir Spring Security observation'ı istemiyorsanız, ObservationRegistry.NOOP @Bean'ini
yayınlayabilirsiniz. Bununla birlikte, bu sadece Spring Security için değil, daha fazlası için observation'ları devre
dışı bırakabilir.

Bunun yerine, aşağıdaki gibi bir ObservationPredicate ile sağlanan ObservationRegistry'yi değiştirebilirsiniz:

```
@Bean
ObservationRegistryCustomizer<ObservationRegistry> noSpringSecurityObservations() {
	ObservationPredicate predicate = (name, context) -> !name.startsWith("spring.security.");
	return (registry) -> registry.observationConfig().observationPredicate(predicate);
}
```

XML desteğiyle observations'i devre dışı bırakmak için bir kolaylık sağlanmamaktadır. Bunun yerine,
observation-registry-ref attribute'unu ayarlamayın veya tanımlamayın. Bu şekilde observations devre dışı bırakılacaktır.

### Trace Listing

Spring Security, her bir request'de aşağıdaki izlemeleri takip eder:

1 - spring.security.http.requests - a span that wraps the entire filter chain, including the request

2 - spring.security.http.chains.before - a span that wraps the receiving part of the security filters

3 - spring.security.http.chains.after - a span that wraps the returning part of the security filters

4 - spring.security.http.secured.requests - a span that wraps the now-secured application request

5 - spring.security.http.unsecured.requests - a span that wraps requests that Spring Security does not secure

6 - spring.security.authentications - a span that wraps authentication attempts

7 - spring.security.authorizations - a span that wraps authorization attempts

Tip :

spring.security.http.chains.before + spring.security.http.secured.requests + spring.security.http.chains.after =
spring.security.http.requests spring.security.http.chains.before + spring.security.http.chains.after = Spring Security’s
part of the request