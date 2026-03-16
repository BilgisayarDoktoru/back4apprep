# Mismatchr Server

Mismatchr uygulamasının WebSocket tabanlı bulut sunucusu.

## Protokol

İstemci bağlantı akışı:

```
İstemci → MISMATCHR_HELLO:<kullanici_adi>
Sunucu  → MISMATCHR_OK   (kabul)
Sunucu  → MISMATCHR_RED  (ret)
Sunucu  → MISMATCHR_BAN  (kalıcı ban)
```

## Güvenlik Katmanları

| # | Koruma | Detay |
|---|---|---|
| 1 | Kara liste | Banlı IP'ler anında reddedilir |
| 2 | Max bağlantı | Aynı anda en fazla 20 istemci |
| 3 | DDoS hız sınırı | IP başına saniyede max 5 bağlantı |
| 4 | Pending flood | Aynı anda max 10 bekleyen el sıkışma |
| 5 | Slowloris | El sıkışma 3 saniyede tamamlanmazsa kesilir |
| 6 | Protokol doğrulama | Yanlış protokol anında reddedilir |
| 7 | Kullanıcı adı sanitize | XSS ve injection karakterleri temizlenir |
| 8 | Duplicate username | Çakışan adlar otomatik #2, #3... olarak değiştirilir |
| 9 | Mesaj flood | IP başına saniyede max 10 mesaj, ihlalde ban |
| 10 | Mesaj boyutu | 512 byte üzeri mesajlar reddedilir |
| 11 | Boş mesaj | Boş ve whitespace mesajlar atlanır |
| 12 | Null byte | Kontrol karakterleri temizlenir |
| 13 | Admin taklit koruması | `ADMIN:` ile başlayan mesajlar reddedilir |
| 14 | Idle timeout | 2 dakika hareketsiz bağlantı otomatik kesilir |
| 15 | Güvenli log | Kullanıcı girdisi log çıktısına yansıtılmaz |

## Ortam Değişkenleri

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `PORT` | `8080` | Dinlenecek port |

## Yerel Çalıştırma

```bash
npm install
node server.js
```

## Back4App Deploy

1. Bu repoyu GitHub'a yükle
2. Back4App → Containers → New Container
3. GitHub reposunu bağla
4. `PORT` = `8080` olarak ayarla
5. Deploy et

## Notlar

- Kara liste yalnızca bellek tabanlıdır; sunucu yeniden başlatılırsa sıfırlanır.
- Admin yönetimi sunucu tarafında harici araç ile yapılır; istemci uygulamasında admin komutu yoktur.
