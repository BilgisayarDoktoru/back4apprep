const WebSocket = require('ws');

// ── Sabitler ────────────────────────────────────────────────
const PORT                      = process.env.PORT || 7777;
const MAX_CONNECTIONS           = 20;
const MAX_PENDING_HANDSHAKES    = 10;
const HANDSHAKE_TIMEOUT_MS      = 3000;
const IDLE_TIMEOUT_MS           = 120000;   // 2 dakika
const MAX_CONN_PER_IP_PER_SEC   = 5;
const MAX_MSG_PER_IP_PER_SEC    = 10;
const MAX_MSG_LENGTH            = 512;      // byte

const HANDSHAKE_PREFIX = 'MISMATCHR_HELLO:';
const HANDSHAKE_OK     = 'MISMATCHR_OK';
const HANDSHAKE_RED    = 'MISMATCHR_RED';
const SISTEM_BAN       = 'MISMATCHR_BAN';

// ── Güvenlik veri yapıları ────────────────────────────────────
const karaListe          = new Set();
const ipBaglantiSayac    = new Map();
const ipSonBaglanti      = new Map();
const ipMesajSayac       = new Map();
const ipSonMesaj         = new Map();
const aktifKullanicilar  = new Set();
const kullaniciMap       = new Map();   // kullaniciAdi -> ws
const kullaniciIpMap     = new Map();   // kullaniciAdi -> ip
const bagliBaglantilar   = new Set();
let   bekleyenElSikisma  = 0;

// ── Koruma 1: DDoS bağlantı hız sınırı ───────────────────────
function ipBaglantiHizKontrol(ip) {
    const now = Date.now();
    if (ipSonBaglanti.has(ip) && (now - ipSonBaglanti.get(ip)) >= 1000)
        ipBaglantiSayac.set(ip, 0);
    ipSonBaglanti.set(ip, now);
    const count = (ipBaglantiSayac.get(ip) || 0) + 1;
    ipBaglantiSayac.set(ip, count);
    return count <= MAX_CONN_PER_IP_PER_SEC;
}

// ── Koruma 2: Mesaj flood ─────────────────────────────────────
function ipMesajHizKontrol(ip) {
    const now = Date.now();
    if (ipSonMesaj.has(ip) && (now - ipSonMesaj.get(ip)) >= 1000)
        ipMesajSayac.set(ip, 0);
    ipSonMesaj.set(ip, now);
    const count = (ipMesajSayac.get(ip) || 0) + 1;
    ipMesajSayac.set(ip, count);
    return count <= MAX_MSG_PER_IP_PER_SEC;
}

// ── Broadcast ─────────────────────────────────────────────────
function broadcast(mesaj, haric = null) {
    for (const client of bagliBaglantilar) {
        if (client === haric) continue;
        if (client.readyState === WebSocket.OPEN)
            client.send(mesaj);
    }
}

// ── Ban komutu ────────────────────────────────────────────────
function banUygula(hedef) {
    if (!kullaniciMap.has(hedef))
        return `Kullanici bulunamadi: ${hedef}`;
    const ws = kullaniciMap.get(hedef);
    const ip = kullaniciIpMap.get(hedef);
    karaListe.add(ip);
    try { ws.send(SISTEM_BAN); } catch (_) {}
    ws.close();
    return `${hedef} banlandi! IP: ${ip}`;
}

// ── WebSocket Sunucusu ────────────────────────────────────────
const wss = new WebSocket.Server({ port: PORT });

wss.on('connection', (ws, req) => {
    // IP tespiti (proxy arkasında da çalışır)
    const gelenIp =
        (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.socket.remoteAddress
        || 'unknown';

    // Koruma 1: Kara liste
    if (karaListe.has(gelenIp)) { ws.close(); return; }

    // Koruma 2: Max bağlantı
    if (bagliBaglantilar.size >= MAX_CONNECTIONS) { ws.close(); return; }

    // Koruma 3: DDoS hız sınırı
    if (!ipBaglantiHizKontrol(gelenIp)) {
        karaListe.add(gelenIp);
        ws.close();
        log(`⚠ DDoS engellendi: ${gelenIp}`);
        return;
    }

    // Koruma 4: Bekleyen el sıkışma flood
    if (++bekleyenElSikisma > MAX_PENDING_HANDSHAKES) {
        bekleyenElSikisma--;
        ws.close();
        return;
    }

    // ── Durum değişkenleri ────────────────────────────────────
    let handshakeDone  = false;
    let kullaniciAdi   = null;
    let idleTimer      = null;

    // Koruma: Slowloris — handshake timeout
    const hsTimeout = setTimeout(() => {
        if (!handshakeDone) {
            ws.close();
            bekleyenElSikisma = Math.max(0, bekleyenElSikisma - 1);
        }
    }, HANDSHAKE_TIMEOUT_MS);

    const resetIdle = () => {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
            log(`${kullaniciAdi} zaman asimi (idle).`);
            ws.close();
        }, IDLE_TIMEOUT_MS);
    };

    // ── Mesaj handler ─────────────────────────────────────────
    ws.on('message', (data) => {
        const msg = data.toString().replace(/[\x00-\x08\x0B-\x1F\x7F]/g, '').trim();

        // ── El sıkışma aşaması ─────────────────────────────
        if (!handshakeDone) {
            clearTimeout(hsTimeout);
            bekleyenElSikisma = Math.max(0, bekleyenElSikisma - 1);
            handshakeDone = true;

            // Koruma 5: Yanlış protokol
            if (!msg.startsWith(HANDSHAKE_PREFIX)) {
                ws.send(HANDSHAKE_RED);
                ws.close();
                return;
            }

            let adi = msg.substring(HANDSHAKE_PREFIX.length).trim();

            // Koruma 6: Boş / uzun kullanıcı adı
            if (!adi || adi.length > 32) adi = gelenIp;

            // Koruma 7: Duplicate username
            if (aktifKullanicilar.has(adi)) {
                let sayac = 2;
                let yeniAd = `${adi}#${sayac}`;
                while (aktifKullanicilar.has(yeniAd))
                    yeniAd = `${adi}#${++sayac}`;
                adi = yeniAd;
            }

            kullaniciAdi = adi;
            ws.send(HANDSHAKE_OK);

            bagliBaglantilar.add(ws);
            kullaniciMap.set(kullaniciAdi, ws);
            kullaniciIpMap.set(kullaniciAdi, gelenIp);
            aktifKullanicilar.add(kullaniciAdi);

            broadcast(`sistem: ${kullaniciAdi} katildi!`, ws);
            log(`✅ ${kullaniciAdi} (${gelenIp}) baglandi. Toplam: ${bagliBaglantilar.size}`);
            resetIdle();
            return;
        }

        // ── Normal mesaj aşaması ──────────────────────────
        resetIdle();

        // Koruma 8: Mesaj flood
        if (!ipMesajHizKontrol(gelenIp)) {
            karaListe.add(gelenIp);
            try { ws.send(SISTEM_BAN); } catch (_) {}
            ws.close();
            log(`⚠ Mesaj flood: ${kullaniciAdi} banlandi.`);
            return;
        }

        // Koruma 9: Mesaj boyutu
        if (Buffer.byteLength(msg, 'utf8') > MAX_MSG_LENGTH) return;

        // Koruma 10: Boş mesaj
        if (!msg) return;

        // ── Sunucu admin komutları ────────────────────────
        // Sadece admin token ile gelen istekler kabul edilir
        const adminToken = process.env.ADMIN_TOKEN || '';
        if (adminToken && msg.startsWith(`ADMIN:${adminToken}:`)) {
            const komut = msg.substring(`ADMIN:${adminToken}:`.length).trim();
            let cevap = '';
            if (komut.startsWith('/ban ')) {
                cevap = banUygula(komut.substring(5).trim());
            } else if (komut === '/banlist') {
                cevap = karaListe.size > 0
                    ? `Kara liste: ${[...karaListe].join(', ')}`
                    : 'Kara liste bos.';
            } else if (komut.startsWith('/unban ')) {
                const hip = komut.substring(7).trim();
                cevap = karaListe.delete(hip)
                    ? `${hip} kaldirildi.`
                    : `${hip} listede degil.`;
            } else if (komut === '/list') {
                cevap = kullaniciMap.size > 0
                    ? `Bagli: ${[...kullaniciMap.keys()].join(', ')}`
                    : 'Kimse bagli degil.';
            }
            if (cevap) { ws.send(`sistem: ${cevap}`); return; }
        }

        // Normal broadcast
        broadcast(msg, ws);
        log(`💬 ${msg}`);
    });

    // ── Bağlantı kapandığında ─────────────────────────────────
    ws.on('close', () => {
        clearTimeout(idleTimer);
        if (!handshakeDone) {
            clearTimeout(hsTimeout);
            bekleyenElSikisma = Math.max(0, bekleyenElSikisma - 1);
        }
        if (kullaniciAdi) {
            bagliBaglantilar.delete(ws);
            kullaniciMap.delete(kullaniciAdi);
            kullaniciIpMap.delete(kullaniciAdi);
            aktifKullanicilar.delete(kullaniciAdi);
            broadcast(`sistem: ${kullaniciAdi} ayrildi.`);
            log(`❌ ${kullaniciAdi} ayrildi. Toplam: ${bagliBaglantilar.size}`);
        }
    });

    ws.on('error', () => ws.close());
});

function log(msg) {
    console.log(`[${new Date().toISOString()}] ${msg}`);
}

log(`🚀 Mismatchr WebSocket sunucusu port ${PORT} uzerinde calisiyor.`);
