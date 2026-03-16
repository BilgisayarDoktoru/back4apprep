const WebSocket = require('ws');

// ── Sabitler ─────────────────────────────────────────────────
const PORT                    = process.env.PORT || 8080;
const MAX_CONNECTIONS         = 20;
const MAX_PENDING_HANDSHAKES  = 10;
const HANDSHAKE_TIMEOUT_MS    = 3000;
const IDLE_TIMEOUT_MS         = 120000;        // 2 dakika hareketsizlik
const MAX_CONN_PER_IP_PER_SEC = 5;
const MAX_MSG_PER_IP_PER_SEC  = 10;
const MAX_MSG_LENGTH          = 512;           // byte
const MAX_USERNAME_LENGTH     = 32;

const HANDSHAKE_PREFIX = 'MISMATCHR_HELLO:';
const HANDSHAKE_OK     = 'MISMATCHR_OK';
const HANDSHAKE_RED    = 'MISMATCHR_RED';
const SISTEM_BAN       = 'MISMATCHR_BAN';

// ── Güvenlik veri yapıları ────────────────────────────────────
const karaListe         = new Set();
const ipBaglantiSayac   = new Map();
const ipSonBaglanti     = new Map();
const ipMesajSayac      = new Map();
const ipSonMesaj        = new Map();
const aktifKullanicilar = new Set();
const kullaniciMap      = new Map();  // kullaniciAdi → ws
const kullaniciIpMap    = new Map();  // kullaniciAdi → ip
const bagliBaglantilar  = new Set();
let   bekleyenElSikisma = 0;

// ── Yardımcı: güvenli log (kullanıcı girdisi direkt basılmaz) ─
function log(seviye, mesaj) {
    const zaman = new Date().toISOString();
    // Kullanıcıdan gelen veri logda gösterilmez — log injection önlemi
    console.log(`[${zaman}] [${seviye}] ${mesaj}`);
}

// ── Koruma: DDoS bağlantı hız sınırı ─────────────────────────
function ipBaglantiHizKontrol(ip) {
    const now = Date.now();
    if (ipSonBaglanti.has(ip) && (now - ipSonBaglanti.get(ip)) >= 1000)
        ipBaglantiSayac.set(ip, 0);
    ipSonBaglanti.set(ip, now);
    const count = (ipBaglantiSayac.get(ip) || 0) + 1;
    ipBaglantiSayac.set(ip, count);
    return count <= MAX_CONN_PER_IP_PER_SEC;
}

// ── Koruma: Mesaj flood ───────────────────────────────────────
function ipMesajHizKontrol(ip) {
    const now = Date.now();
    if (ipSonMesaj.has(ip) && (now - ipSonMesaj.get(ip)) >= 1000)
        ipMesajSayac.set(ip, 0);
    ipSonMesaj.set(ip, now);
    const count = (ipMesajSayac.get(ip) || 0) + 1;
    ipMesajSayac.set(ip, count);
    return count <= MAX_MSG_PER_IP_PER_SEC;
}

// ── Kullanıcı adı sanitize (XSS / injection önlemi) ──────────
function sanitizeAd(adi) {
    return adi
        .replace(/[^\w\u00C0-\u024F\u4E00-\u9FFF _\-\.]/g, '')  // sadece harf/rakam/unicode
        .substring(0, MAX_USERNAME_LENGTH)
        .trim();
}

// ── Broadcast ─────────────────────────────────────────────────
function broadcast(mesaj, haric = null) {
    const data = mesaj.substring(0, MAX_MSG_LENGTH * 2); // broadcast da uzunluk sınırı
    for (const client of bagliBaglantilar) {
        if (client === haric) continue;
        if (client.readyState === WebSocket.OPEN)
            try { client.send(data); } catch (_) {}
    }
}

// ── Kullanıcı temizle ─────────────────────────────────────────
function kullaniciyiTemizle(ws, kullaniciAdi, handshakeDone) {
    if (!handshakeDone) {
        bekleyenElSikisma = Math.max(0, bekleyenElSikisma - 1);
    }
    if (kullaniciAdi) {
        bagliBaglantilar.delete(ws);
        kullaniciMap.delete(kullaniciAdi);
        kullaniciIpMap.delete(kullaniciAdi);
        aktifKullanicilar.delete(kullaniciAdi);
        broadcast(`sistem: Bir kullanici ayrildi. (${bagliBaglantilar.size}/${MAX_CONNECTIONS})`);
        log('INFO', `Kullanici ayrildi. Toplam: ${bagliBaglantilar.size}`);
    }
}

// ── WebSocket Sunucusu ────────────────────────────────────────
const wss = new WebSocket.Server({ port: PORT });

wss.on('connection', (ws, req) => {

    // IP tespiti — proxy arkasında da çalışır
    const gelenIp = (
        (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
        req.socket?.remoteAddress ||
        'unknown'
    ).replace(/^::ffff:/, ''); // IPv4-mapped IPv6 temizle

    // ── Koruma 1: Kara liste ──────────────────────────────────
    if (karaListe.has(gelenIp)) { ws.close(); return; }

    // ── Koruma 2: Max bağlantı ────────────────────────────────
    if (bagliBaglantilar.size >= MAX_CONNECTIONS) {
        ws.close();
        log('WARN', `Max baglanti asimi. Red: ${gelenIp}`);
        return;
    }

    // ── Koruma 3: DDoS bağlantı hız sınırı ───────────────────
    if (!ipBaglantiHizKontrol(gelenIp)) {
        karaListe.add(gelenIp);
        ws.close();
        log('WARN', `DDoS engellendi: ${gelenIp}`);
        return;
    }

    // ── Koruma 4: Bekleyen el sıkışma flood ───────────────────
    if (++bekleyenElSikisma > MAX_PENDING_HANDSHAKES) {
        bekleyenElSikisma--;
        ws.close();
        return;
    }

    // ── Durum ─────────────────────────────────────────────────
    let handshakeDone = false;
    let kullaniciAdi  = null;
    let idleTimer     = null;

    // ── Koruma 5: Slowloris — el sıkışma timeout ──────────────
    const hsTimeout = setTimeout(() => {
        if (!handshakeDone) {
            ws.close();
            bekleyenElSikisma = Math.max(0, bekleyenElSikisma - 1);
            log('WARN', `Handshake timeout: ${gelenIp}`);
        }
    }, HANDSHAKE_TIMEOUT_MS);

    // ── Idle timer (her mesajda sıfırlanır) ───────────────────
    const resetIdle = () => {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
            // Idle mesajında kullanıcı adı GÖSTERILMEZ — log injection önlemi
            log('INFO', `Idle timeout. IP: ${gelenIp}`);
            // Bağlı kullanıcıya sadece genel bilgi
            try { ws.send('sistem: Uzun süre hareketsiz kaldınız, bağlantınız kesildi.'); } catch (_) {}
            ws.close();
        }, IDLE_TIMEOUT_MS);
    };

    // ── Mesaj handler ─────────────────────────────────────────
    ws.on('message', (rawData) => {

        // ── Koruma 6: Binary veri reddi ───────────────────────
        if (Buffer.isBuffer(rawData) && rawData.length > MAX_MSG_LENGTH) {
            ws.close(); return;
        }

        // Null byte ve kontrol karakteri temizle
        const msg = rawData.toString('utf8')
            .replace(/[\x00-\x08\x0B-\x1F\x7F]/g, '')
            .trim();

        // ── El sıkışma ────────────────────────────────────────
        if (!handshakeDone) {
            clearTimeout(hsTimeout);
            bekleyenElSikisma = Math.max(0, bekleyenElSikisma - 1);
            handshakeDone = true;

            // ── Koruma 7: Yanlış protokol ─────────────────────
            if (!msg.startsWith(HANDSHAKE_PREFIX)) {
                try { ws.send(HANDSHAKE_RED); } catch (_) {}
                ws.close();
                log('WARN', `Yanlis protokol: ${gelenIp}`);
                return;
            }

            let adi = msg.substring(HANDSHAKE_PREFIX.length).trim();

            // ── Koruma 8: Boş / uzun kullanıcı adı ───────────
            if (!adi || adi.length < 1) { adi = 'anonim'; }

            // ── Koruma 9: Kullanıcı adı sanitize ─────────────
            adi = sanitizeAd(adi);
            if (!adi) adi = 'kullanici';

            // ── Koruma 10: Duplicate username ─────────────────
            if (aktifKullanicilar.has(adi)) {
                let sayac = 2;
                let yeniAd = `${adi}#${sayac}`;
                while (aktifKullanicilar.has(yeniAd) && sayac < 999)
                    yeniAd = `${adi}#${++sayac}`;
                adi = yeniAd;
            }

            kullaniciAdi = adi;
            try { ws.send(HANDSHAKE_OK); } catch (_) { ws.close(); return; }

            bagliBaglantilar.add(ws);
            kullaniciMap.set(kullaniciAdi, ws);
            kullaniciIpMap.set(kullaniciAdi, gelenIp);
            aktifKullanicilar.add(kullaniciAdi);

            // Katılma bildirimi — kullanıcı adı sanitize edilmiş
            broadcast(`sistem: ${kullaniciAdi} katildi! (${bagliBaglantilar.size}/${MAX_CONNECTIONS})`, ws);
            log('INFO', `Baglandi. Toplam: ${bagliBaglantilar.size}`);
            resetIdle();
            return;
        }

        // ── Normal mesaj ──────────────────────────────────────
        resetIdle();

        // ── Koruma 11: Mesaj flood ────────────────────────────
        if (!ipMesajHizKontrol(gelenIp)) {
            karaListe.add(gelenIp);
            try { ws.send(SISTEM_BAN); } catch (_) {}
            ws.close();
            log('WARN', `Mesaj flood bani: ${gelenIp}`);
            return;
        }

        // ── Koruma 12: Mesaj boyutu ───────────────────────────
        if (Buffer.byteLength(msg, 'utf8') > MAX_MSG_LENGTH) {
            log('WARN', `Uzun mesaj reddedildi: ${gelenIp}`);
            return;
        }

        // ── Koruma 13: Boş mesaj ──────────────────────────────
        if (!msg) return;

        // ── Koruma 14: ADMIN komutu taklidi engeli ────────────
        // Client'tan ADMIN: ile başlayan mesajlar doğrudan reddedilir
        // (AdminPanel ayrı bir araçtır, client'ta yoktur)
        if (msg.startsWith('ADMIN:')) {
            log('WARN', `Yetkisiz admin denemesi: ${gelenIp}`);
            return;
        }

        // Normal broadcast
        broadcast(msg, ws);
        log('MSG', `[${kullaniciAdi?.substring(0,8) ?? '?'}...] iletildi`);
    });

    // ── Bağlantı kapandığında ─────────────────────────────────
    ws.on('close', () => {
        clearTimeout(idleTimer);
        clearTimeout(hsTimeout);
        kullaniciyiTemizle(ws, kullaniciAdi, handshakeDone);
    });

    ws.on('error', (err) => {
        log('ERROR', `WS hatasi: ${err.code ?? 'unknown'}`);
        ws.close();
    });
});

wss.on('error', (err) => {
    log('FATAL', `Sunucu hatasi: ${err.message}`);
});

log('INFO', `Mismatchr sunucusu calisiyor. Port: ${PORT} | Max: ${MAX_CONNECTIONS} baglanti`);
