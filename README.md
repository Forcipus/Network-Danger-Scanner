Network Danger Scanner (Threat Intelligence API)

Bu proje, şüpheli IP adreslerini, alan adlarını ve URL'leri analiz etmek için birden fazla istihbarat kaynağını tek bir çatı altında toplayan bir Threat Intelligence Aggregator (Tehdit İstihbarat Toplayıcı) aracıdır. Özellikle siber güvenlik analistlerinin manuel olarak yaptığı sorgulama süreçlerini otomatize ederek, tek bir sorguyla en popüler üç servisten veri çekilmesini sağlar.

Projenin Temel Amacı ve Vizyonu

Günümüz siber tehdit manzarasında bir göstergeyi (IoC) analiz etmek vakit alıcıdır. Bu uygulama, kullanıcıdan aldığı tek bir girdiyi (gerekirse DNS çözümlemesi yaparak) analiz eder ve aşağıdaki platformlardan gerçek zamanlı veri toplar:

    VirusTotal: Dosya itibar analizi ve topluluk yorumları.

    AbuseIPDB: IP'nin daha önce raporlanmış saldırı geçmişi ve güven skoru.

    Shodan: Hedef sistemin açık portları, üzerinde koşan servisler ve banner bilgileri.

Teknik Mimari ve Fonksiyonlar
1. Akıllı İstihbarat Toplama (Backend Logic)

Uygulama, kullanıcının ne girdiğini (IP mi yoksa bir URL mi?) otomatik olarak ayırt eder. Eğer bir URL/Domain girilirse, Dns.GetHostAddressesAsync metodu üzerinden asenkron olarak arka planda IP çözümlemesi yapılır.

    HttpClientFactory: Dış API'lere yapılan isteklerde bağlantı havuzu yönetimi ve performans için IHttpClientFactory kullanılmıştır.

    JsonElement & Memory Management: API'lerden gelen dinamik JSON verileri JsonElement tipiyle karşılanır ve hafıza sızıntılarını önlemek adına .Clone() yöntemiyle model içine güvenli bir şekilde aktarılır.

2. Risk Skorlama Algoritması

Sadece veriyi getirmekle kalmıyoruz; AbuseIPDB üzerinden gelen abuseConfidenceScore değerini işleyerek kullanıcıya "Düşük", "Orta" veya "Yüksek" şeklinde anlaşılır bir risk etiketi sunuyoruz.
3. Veritabanı ve Kalıcılık (MongoDB)

Analiz edilen veriler uçup gitmez. MongoService.cs katmanı üzerinden MongoDB'ye asenkron olarak kaydedilir.

    Koleksiyon Yönetimi: Veriler, appsettings.json üzerinden yapılandırılan koleksiyonlarda, zaman damgasıyla (Timestamp) birlikte saklanır.

    CRUD İşlemleri: Geçmiş raporlar listenlenebilir ve ihtiyaç duyulmadığında benzersiz ID'leri üzerinden silinebilir.

Dosya Yapısı ve Sorumluluklar

Dosya	Görev


ThreatIntelController.cs	
API çağrılarının, DNS çözümlemenin ve risk skorlamanın yapıldığı ana beyin.

MongoService.cs	
MongoDB bağlantısı, rapor kaydetme ve silme işlemlerini yürüten servis.

ThreatReport.cs	
API'lerden gelen karmaşık verileri ve veritabanı şemasını tutan model.

Index.cshtml	
Bootstrap tabanlı, asenkron fetch istekleriyle çalışan kullanıcı arayüzü.

appsettings.json	
API anahtarları ve veritabanı bağlantı bilgilerinin tutulduğu merkez.
