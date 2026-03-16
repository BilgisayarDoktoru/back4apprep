# Mismatchr Server

Mismatchr uygulamasinin WebSocket tabanli bulut sunucusu.  
C# istemcisiyle ayni el sikisma protokolunu kullanir: `MISMATCHR_HELLO / MISMATCHR_OK / MISMATCHR_RED / MISMATCHR_BAN`

## Guvenlik ozellikleri

- Kara liste (IP ban)
- Maks. 20 eszamanli baglanti
- DDoS baglantibaslanti hiz siniri (IP basina 5/sn)
- Slowloris korumasihandshake timeout (3 sn)
- Yanlis protokol reddi
- Duplicate username duzeltme
- Zombie connection temizleme (2 dk idle)
- Mesaj boyutu siniri (512 byte)
- Mesaj flood bani (IP basina 10/sn)
- Null byte temizleme

## Ortam degiskenleri

| Degisken | Varsayilan | Aciklama |
|---|---|---|
| `PORT` | `7777` | Dinlenecek port |
| `ADMIN_TOKEN` | *(bos)* | Admin komutu sifresi |

## Yerel calistirma

```bash
npm install
node server.js
```

## Back4App deploy

1. Bu repoyu GitHub'a yukle
2. Back4App > Containers > New Container
3. GitHub reposunu bagla
4. `PORT` ortam degiskenini `7777` olarak ayarla
5. Deploy et

## Admin komutlari

Sunucuya baglanmis bir istemciden su formatta gonderin:

```
ADMIN:<token>:/ban KullaniciAdi
ADMIN:<token>:/unban 1.2.3.4
ADMIN:<token>:/banlist
ADMIN:<token>:/list
```
