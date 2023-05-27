# Authorization

Kullanıcıların nasıl kimlik doğrulaması yapacaklarını belirledikten sonra, uygulamanızın authorization rules'larını da
yapılandırmanız gerekir.

Kimlik doğrulama yöntemini (Spring Security tarafından sağlanan mekanizma ve sağlayıcı veya bir konteyner veya başka bir
Spring Security kimlik doğrulama yetkilisi ile entegrasyon) nasıl seçerseniz seçin, yetkilendirme hizmetleri
uygulamanızda tutarlı ve basit bir şekilde kullanılabilir. Spring Security, uygulamanızdaki kaynaklara erişim kontrol
kurallarını tanımlamanız ve uygulamanızda uygulamanızı zorlamak için kullanabileceğiniz bir dizi yetkilendirme hizmeti
sağlar

Spring Security, uygulamanızdaki kaynaklara erişim kontrolü için bir dizi yetkilendirme mekanizması sunar. Bu
mekanizmalar, kullanıcıların rollerine, izinlerine veya diğer kimlik doğrulama faktörlerine dayalı olarak istekleri
denetler ve uygun erişim kontrolünü uygular.