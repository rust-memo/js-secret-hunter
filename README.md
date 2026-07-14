# JS Secret Hunter 1.1

إضافة حديثة لـBurp Suite Community وProfessional مبنية بـJava 17 وMontoya API.
تراجع مرور Target Scope في Proxy History والمرور الجديد، وتحلل JavaScript وHTML
وJSON وXML وsource maps وبقية الاستجابات النصية، ثم تبحث محليًا عن مفاتيح API
واعتماديات ومسارات إدارية وواجهات مخفية.

## ضمانات الأمان

- أي جلب تلقائي مقيد دائمًا بـ**Target Scope**.
- تورث `Cookie` و`Authorization` من الطلب الأب لنفس `scheme/host/port` فقط.
- الانتقال إلى أصل آخر داخل Scope يستخدم طلبًا بلا اعتماديات الطلب الأب.
- كل وجهة redirect يجب أن تبقى داخل Scope، وبحد أقصى 3 redirects.
- لا تنفذ الإضافة JavaScript، ولا تختبر صلاحية المفاتيح، ولا ترسل النتائج إلى طرف ثالث.
- القيم مخفية افتراضيًا ولا تحفظها الإضافة في Preferences أو project data.
- الفحص اليدوي لرسالة خارج Scope يحلل الاستجابة الموجودة فقط ولا يرسل طلبات إضافية.
- Audit Issues اليدوية تستخدم قيمة منقحة وبصمة SHA-256 بدل كتابة السر الخام في الوصف.

استخدم الإضافة فقط على الأنظمة التي تملك تصريحًا صريحًا لاختبارها. إضافة الهدف إلى
Target Scope تعني أن الإضافة قد ترسل طلبات GET تلقائية إلى ملفات JavaScript المكتشفة فيه.

## ما الذي تكتشفه؟

- مفاتيح AWS وGitHub وGitLab وStripe وSlack وGoogle/Firebase وOpenAI وAnthropic
  وHugging Face وSendGrid وTwilio وغيرها.
- JWT، private keys، Bearer tokens، Basic Auth، webhook URLs، database connection URIs.
- `api_key`, `client_secret`, `access_token`, `password`, `username` والقيم المشابهة
  باستخدام السياق وentropy وallowlists لتقليل الضوضاء.
- API وadmin/debug/internal routes وGraphQL وWebSocket وcloud storage وملفات config/env.
- نصوص JavaScript المهربة وBase64 المحدود و`sourcesContent` داخل source maps.
- ملفات script وmodulepreload بلا امتداد عندما تأتي من HTML أو static import موثوق.

النتائج مصنفة حسب **Severity** و**Confidence** بصورة منفصلة؛ النتيجة مرشح للمراجعة
وليست إثباتًا أن المفتاح ما زال صالحًا أو أن المسار قابل للاستغلال.

## البناء والتثبيت

يتطلب JDK 17 أو أحدث حتى Java 21:

```bash
./gradlew clean test jar
```

حمّل الملف التالي من **Extensions > Installed > Add > Java**:

```text
build/libs/js-secret-hunter-1.1.0.jar
```

GitHub Actions runs the tests and publishes this JAR as a directly downloadable workflow artifact. Attach the tested JAR to a versioned GitHub Release for end users; do not commit the local `build/` directory.

بعد التحميل، افتح تبويب **JS Secret Hunter**. يبدأ فحص History تلقائيًا. اضبط
Target Scope قبل تفعيل أو استخدام الجلب الخلفي.

## الواجهة

- **Findings:** بحث وفلاتر Severity/Confidence/Kind/Status وعارض Request/Response وحالات review وfalse positive.
- **Assets:** حالة كل ملف، عمق الاكتشاف، الصفحة الأم، وسبب التخطي أو الفشل.
- **Rules:** إصدار الحزمة وSHA-256 واستيراد حزمة JSON يدويًا من ملف أو HTTPS.
- **Settings:** نطاق التحليل وحدود History والنتائج والعمق والحجم والمهلة والتزامن لكل host.
- **Reveal / Copy:** يتطلبان تأكيدًا قبل كشف القيمة الخام.
- **Export:** JSON وCSV للعرض المفلتر أو كل النتائج؛ التصدير الكامل له تحذير مستقل.
- **Context menu:** استخدم `Scan with JS Secret Hunter` لتحليل الرسائل المحددة يدويًا.
- **Add as Burp issue:** متاح فقط لنتيجة Reviewed ولمرة واحدة لكل fingerprint.

يمكن إيقاف Queue مؤقتًا أو إلغاء الأعمال المنتظرة. الطلب الجاري عند الضغط على
`Cancel queued` قد يكمل على الشبكة لأن Montoya لا يوقف socket قيد التنفيذ، لكن
استجابته تُهمل ولا تستطيع إعادة النتائج الملغاة. يعرض شريط الحالة queued وactive
وscanned وfindings، وتتحول الأصول الملغاة إلى `CANCELLED`.

## حزم القواعد

الملف يجب ألا يتجاوز 5MB، ويستخدم RE2-compatible regex لتجنب catastrophic
backtracking. الاستيراد ذري: لا تستبدل الحزمة الحالية إلا بعد نجاح التحقق الكامل
وموافقة المستخدم.

```json
{
  "schemaVersion": 1,
  "version": "2026.07.2-custom",
  "releasedAt": "2026-07-13",
  "rules": [{
    "id": "vendor-token",
    "name": "Vendor token",
    "kind": "SECRET",
    "severity": "HIGH",
    "confidence": "HIGH",
    "keywords": ["vendor_"],
    "regex": "\\b(vendor_[A-Za-z0-9]{32})\\b",
    "secretGroup": 1,
    "minEntropy": 3.0,
    "minLength": 39,
    "allowlistRegex": "(?i)(example|sample)",
    "enabled": true
  }]
}
```

الأنواع المقبولة: `SECRET`, `CREDENTIAL`, `ENDPOINT`, `IDENTIFIER`,
`CONFIGURATION`. درجات الخطورة: `CRITICAL`, `HIGH`, `MEDIUM`, `INFO`.

## حدود معروفة

- التحليل static ولا يحل JavaScript المحجوب بشدة ولا ينفذ bundler runtime.
- Brotli وZstandard لا يُفكان داخل الإضافة؛ الاستجابة التي يقدمها Burp مفكوكة مسبقًا
  ستُفحص بصورة طبيعية.
- لا يعني high entropy وحده وجود سر؛ يجب مراجعة السياق يدويًا.
- تغيير query string ينتج asset مستقلًا لأن الإصدارات المختلفة قد تحتوي محتوى مختلفًا.

---

## English summary

JS Secret Hunter passively analyzes in-scope JavaScript and text responses and can safely
fetch missing in-scope assets in the background. It also supports local context-menu scans
and redacted manual Burp audit issues. Same-origin credentials are never forwarded across
origins, values are masked by default, and no credential validation or third-party submission
occurs. Build with `./gradlew clean test jar`, then load the resulting JAR as a Java extension.

## License

MIT. See [LICENSE](LICENSE). Runtime dependency notices are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
