// Deno Deploy — Mismatchr WebSocket Sunucusu

// ── Sabitler ─────────────────────────────────────────────────
const MAX_CONNECTIONS         = 20;
const MAX_PENDING_HANDSHAKES  = 10;
const HANDSHAKE_TIMEOUT_MS    = 3000;
const IDLE_TIMEOUT_MS         = 120000;
const MAX_CONN_PER_IP_PER_SEC = 5;
const MAX_MSG_PER_IP_PER_SEC  = 10;
const MAX_MSG_LENGTH          = 512;
const MAX_USERNAME_LENGTH     = 32;

const HANDSHAKE_PREFIX = "MISMATCHR_HELLO:";
const HANDSHAKE_OK     = "MISMATCHR_OK";
const HANDSHAKE_RED    = "MISMATCHR_RED";
const SISTEM_BAN       = "MISMATCHR_BAN";

// ── Güvenlik veri yapıları ────────────────────────────────────
const karaListe         = new Set();
const ipBaglantiSayac   = new Map();
const ipSonBaglanti     = new Map();
const ipMesajSayac      = new Map();
const ipSonMesaj        = new Map();
const aktifKullanicilar = new Set();
const kullaniciMap      = new Map();
const kullaniciIpMap    = new Map();
const bagliBaglantilar  = new Set();
let   bekleyenElSikisma = 0;

function log(seviye, mesaj) {
    console.log(`[${new Date().toISOString()}] [${seviye}] ${mesaj}`);
}

function ipBaglantiHizKontrol(ip) {
    const now = Date.now();
    if (ipSonBaglanti.has(ip) && (now - ipSonBaglanti.get(ip)) >= 1000)
        ipBaglantiSayac.set(ip, 0);
    ipSonBaglanti.set(ip, now);
    const count = (ipBaglantiSayac.get(ip) || 0) + 1;
    ipBaglantiSayac.set(ip, count);
    return count <= MAX_CONN_PER_IP_PER_SEC;
}

function ipMesajHizKontrol(ip) {
    const now = Date.now();
    if (ipSonMesaj.has(ip) && (now - ipSonMesaj.get(ip)) >= 1000)
        ipMesajSayac.set(ip, 0);
    ipSonMesaj.set(ip, now);
    const count = (ipMesajSayac.get(ip) || 0) + 1;
    ipMesajSayac.set(ip, count);
    return count <= MAX_MSG_PER_IP_PER_SEC;
}

function sanitizeAd(adi) {
    return adi
        .replace(/[^\w\u00C0-\u024F\u4E00-\u9FFF _\-\.]/g, "")
        .substring(0, MAX_USERNAME_LENGTH)
        .trim();
}

function broadcast(mesaj, haric = null) {
    const data = mesaj.substring(0, MAX_MSG_LENGTH * 2);
    for (const client of bagliBaglantilar) {
        if (client === haric) continue;
        if (client.readyState === WebSocket.OPEN)
            try { client.send(data); } catch (_) {}
    }
}

function kullaniciyiTemizle(ws, kullaniciAdi, handshakeDone) {
    if (!handshakeDone)
        bekleyenElSikisma = Math.max(0, bekleyenElSikisma - 1);
    if (kullaniciAdi) {
        bagliBaglantilar.delete(ws);
        kullaniciMap.delete(kullaniciAdi);
        kullaniciIpMap.delete(kullaniciAdi);
        aktifKullanicilar.delete(kullaniciAdi);
        broadcast(`sistem: Bir kullanici ayrildi. (${bagliBaglantilar.size}/${MAX_CONNECTIONS})`);
        log("INFO", `Kullanici ayrildi. Toplam: ${bagliBaglantilar.size}`);
    }
}

// ── HTTP + WebSocket handler ──────────────────────────────────
Deno.serve((req) => {
    // Sağlık kontrolü için HTTP GET
    if (req.method === "GET" && !req.headers.get("upgrade")) {
        return new Response("Mismatchr sunucusu calisiyor.", { status: 200 });
    }

    // WebSocket yükseltme
    if (req.headers.get("upgrade") !== "websocket") {
        return new Response("WebSocket gerekli.", { status: 426 });
    }

    const gelenIp = (
        req.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
        req.headers.get("cf-connecting-ip") ||
        "unknown"
    ).replace(/^::ffff:/, "");

    // ── Koruma 1: Kara liste ──────────────────────────────────
    if (karaListe.has(gelenIp)) {
        return new Response("Yasakli.", { status: 403 });
    }

    // ── Koruma 2: Max bağlantı ────────────────────────────────
    if (bagliBaglantilar.size >= MAX_CONNECTIONS) {
        return new Response("Sunucu dolu.", { status: 503 });
    }

    // ── Koruma 3: DDoS hız sınırı ─────────────────────────────
    if (!ipBaglantiHizKontrol(gelenIp)) {
        karaListe.add(gelenIp);
        log("WARN", `DDoS engellendi: ${gelenIp}`);
        return new Response("Cok fazla baglanti.", { status: 429 });
    }

    // ── Koruma 4: Pending flood ───────────────────────────────
    if (++bekleyenElSikisma > MAX_PENDING_HANDSHAKES) {
        bekleyenElSikisma--;
        return new Response("Sunucu mesgul.", { status: 503 });
    }

    const { socket: ws, response } = Deno.upgradeWebSocket(req);

    let handshakeDone = false;
    let kullaniciAdi  = null;
    let idleTimer     = null;

    // ── Koruma 5: Slowloris ───────────────────────────────────
    const hsTimeout = setTimeout(() => {
        if (!handshakeDone) {
            ws.close();
            bekleyenElSikisma = Math.max(0, bekleyenElSikisma - 1);
            log("WARN", `Handshake timeout: ${gelenIp}`);
        }
    }, HANDSHAKE_TIMEOUT_MS);

    const resetIdle = () => {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
            log("INFO", `Idle timeout: ${gelenIp}`);
            try { ws.send("sistem: Uzun sure hareketsiz kaldiniz, baglantiiniz kesildi."); } catch (_) {}
            ws.close();
        }, IDLE_TIMEOUT_MS);
    };

    ws.onopen = () => {
        log("INFO", `Yeni baglanti: ${gelenIp}`);
    };

    ws.onmessage = (event) => {
        const msg = event.data
            .toString()
            .replace(/[\x00-\x08\x0B-\x1F\x7F]/g, "")
            .trim();

        // ── El sıkışma ────────────────────────────────────────
        if (!handshakeDone) {
            clearTimeout(hsTimeout);
            bekleyenElSikisma = Math.max(0, bekleyenElSikisma - 1);
            handshakeDone = true;

            if (!msg.startsWith(HANDSHAKE_PREFIX)) {
                try { ws.send(HANDSHAKE_RED); } catch (_) {}
                ws.close();
                log("WARN", `Yanlis protokol: ${gelenIp}`);
                return;
            }

            let adi = msg.substring(HANDSHAKE_PREFIX.length).trim();
            if (!adi) adi = "anonim";
            adi = sanitizeAd(adi);
            if (!adi) adi = "kullanici";

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

            broadcast(`sistem: ${kullaniciAdi} katildi! (${bagliBaglantilar.size}/${MAX_CONNECTIONS})`, ws);
            log("INFO", `Baglandi. Toplam: ${bagliBaglantilar.size}`);
            resetIdle();
            return;
        }

        // ── Normal mesaj ──────────────────────────────────────
        resetIdle();

        if (!ipMesajHizKontrol(gelenIp)) {
            karaListe.add(gelenIp);
            try { ws.send(SISTEM_BAN); } catch (_) {}
            ws.close();
            log("WARN", `Mesaj flood bani: ${gelenIp}`);
            return;
        }

        if (new TextEncoder().encode(msg).length > MAX_MSG_LENGTH) return;
        if (!msg) return;
        if (msg.startsWith("ADMIN:")) {
            log("WARN", `Yetkisiz admin denemesi: ${gelenIp}`);
            return;
        }

        broadcast(msg, ws);
        log("MSG", `[${kullaniciAdi?.substring(0, 8) ?? "?"}...] iletildi`);
    };

    ws.onclose = () => {
        clearTimeout(idleTimer);
        clearTimeout(hsTimeout);
        kullaniciyiTemizle(ws, kullaniciAdi, handshakeDone);
    };

    ws.onerror = () => ws.close();

    return response;
});

log("INFO", `Mismatchr Deno sunucusu calisiyor. Max: ${MAX_CONNECTIONS} baglanti`);
