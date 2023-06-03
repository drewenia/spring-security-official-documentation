# Jackson Supoort

Spring Security, Spring Security ile ilgili sınıfları kalıcı hale getirmek için Jackson desteği sağlar. Bu destek,
distrubuted session'lar ile (oturum replikasyonu, Spring Session vb.) çalışırken Spring Security ile ilgili sınıfların
serialize hale getirilme performansını artırabilir.

Kullanmak için, ObjectMapper (jackson-databind) ile SecurityJackson2Modules.getModules(ClassLoader)'ı kaydetmeniz
gerekmektedir. Bu işlem aşağıdaki gibi gerçekleştirilebilir:

```
ObjectMapper mapper = new ObjectMapper();
ClassLoader loader = getClass().getClassLoader();
List<Module> modules = SecurityJackson2Modules.getModules(loader);
mapper.registerModules(modules);

// ... use ObjectMapper as normally ...
SecurityContext context = new SecurityContextImpl();
// ...
String json = mapper.writeValueAsString(context);
```

Aşağıdaki Spring Security modülleri, Jackson desteği sağlar:

- spring-security-core (CoreJackson2Module)
- spring-security-web (WebJackson2Module, WebServletJackson2Module, WebServerJackson2Module)
- spring-security-oauth2-client (OAuth2ClientJackson2Module)
- spring-security-cas (CasJackson2Module)