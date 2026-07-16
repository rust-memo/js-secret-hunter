# JS Secret Hunter 1.3

إضافة حديثة لـBurp Suite Community وProfessional مبنية بـJava 17 وMontoya API.
تراجع كل الردود المحفوظة في Proxy History والمرور الجديد محليًا في الخلفية، وتحلل JavaScript وHTML
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
- مرشحات ثغرات client-side: DOM XSS sinks و`eval`/`Function` وclient-side open redirect
  وwildcard `postMessage` وتعطيل TLS verification وتخزين tokens في Web Storage
  وprototype pollution وWebSocket غير المشفر. هذه إشارات static تحتاج مراجعة data flow يدويًا.
- روابط التطبيقات العامة داخل النصوص المقتبسة، بما فيها المسارات النسبية وURLs الكاملة،
  بفئة ثقة منخفضة منفصلة لتسهيل المراجعة دون خلطها بالقواعد المتخصصة.
- نصوص JavaScript المهربة وBase64 المحدود و`sourcesContent` داخل source maps.
- ملفات script وmodulepreload بلا امتداد، وimports/exports وWeb/Shared/Service Workers
  وinline module imports.

النتائج مصنفة حسب **Severity** و**Confidence** بصورة منفصلة؛ النتيجة مرشح للمراجعة
وليست إثباتًا أن المفتاح ما زال صالحًا أو أن المسار قابل للاستغلال.

## البناء والتثبيت

يتطلب JDK 17 أو أحدث حتى Java 21:

```bash
./gradlew clean test jar
```

حمّل الملف التالي من **Extensions > Installed > Add > Java**:

```text
build/libs/js-secret-hunter-1.3.0.jar
```

GitHub Actions runs the tests and publishes this JAR as a directly downloadable workflow artifact. Attach the tested JAR to a versioned GitHub Release for end users; do not commit the local `build/` directory.

بعد التحميل، افتح تبويب **JS Secret Hunter**. يبدأ فحص History تلقائيًا. اضبط
Target Scope قبل تفعيل أو استخدام الجلب الخلفي.

## الواجهة

- **Overview:** لوحة مستوحاة من نسخة Caido تعرض critical/high exposure وvulnerability candidates
  والملفات الحساسة والـattack surface ونسبة إنجاز المراجعة وآخر النتائج وحالة الفحص.
- **Findings:** بحث وفلاتر Severity/Confidence/Kind/Status وعارض Request/Response وحالات review وfalse positive.
- **Sensitive Files:** صف واحد لكل ملف به نتائج، مع Request/Response من History وتصنيف كل نتائج الملف دفعة واحدة.
- **Links:** بحث وفرز للمسارات المكتشفة، URL كامل للمسارات النسبية، نسخ مباشر، وإرسال
  endpoint أو ملف المصدر إلى Repeater دون تنفيذ الطلب تلقائيًا.
- **Assets:** بحث وفلتر للحالة، عمق الاكتشاف، الصفحة الأم، وسبب التخطي أو الفشل.
- **Rules:** إصدار الحزمة وSHA-256 واستيراد حزمة JSON يدويًا من ملف أو HTTPS.
- **Settings:** نطاق التحليل وحدود History والنتائج والعمق والحجم والمهلة والتزامن لكل host.
- **Asset exclusions:** قائمة URL fragments قابلة للضبط تمنع الجلب الخلفي لملفات vendor
  المزعجة فقط؛ أي رد موجود في History يظل خاضعًا للتحليل المحلي.
- **Reveal / Copy:** يتطلبان تأكيدًا قبل كشف القيمة الخام، بينما نسخ الروابط والتصدير المنقح
  يخفي credentials وtoken/signature query parameters تلقائيًا.
- **Export:** JSON وCSV للعرض المفلتر أو كل النتائج؛ التصدير الكامل له تحذير مستقل.
- **Context menu:** استخدم `Scan with JS Secret Hunter` لتحليل الرسائل المحددة يدويًا.
- **Add as Burp issue:** متاح فقط لنتيجة Reviewed ولمرة واحدة لكل fingerprint.

تظهر الملفات التي تحتوي نتائج داخل **Sensitive Files**، وتظهر النتائج التفصيلية والروابط
داخل تبويبي **Findings** و**Links**. الكتابة في Proxy History Notes
متوقفة افتراضيًا ويمكن تفعيلها اختياريًا من Settings. عند إعادة الفحص تنظف الإضافة
مقاطع Notes القديمة التي أنشأتها هي فقط، ولا تمس ملاحظات المحلل الأخرى.

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
  "version": "2026.07.4-custom",
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

الأنواع المقبولة: `SECRET`, `CREDENTIAL`, `VULNERABILITY`, `ENDPOINT`, `IDENTIFIER`,
`CONFIGURATION`. يمكن إضافة `description` و`remediation` و`sensitiveValue` لكل قاعدة.
درجات الخطورة: `CRITICAL`, `HIGH`, `MEDIUM`, `INFO`.

## حدود معروفة

- التحليل static ولا يحل JavaScript المحجوب بشدة ولا ينفذ bundler runtime.
- Brotli وZstandard لا يُفكان داخل الإضافة؛ الاستجابة التي يقدمها Burp مفكوكة مسبقًا
  ستُفحص بصورة طبيعية.
- لا يعني high entropy وحده وجود سر؛ يجب مراجعة السياق يدويًا.
- تغيير query string ينتج asset مستقلًا لأن الإصدارات المختلفة قد تحتوي محتوى مختلفًا.

---

## English summary

JS Secret Hunter passively analyzes all stored and live Proxy JavaScript/text responses locally and can safely
fetch missing in-scope assets in the background. Sensitive Files groups findings by source message for
Request/Response review and bulk classification. It also supports local context-menu scans
and redacted manual Burp audit issues. Version 1.3 adds a Caido-inspired Overview dashboard and
confidence-calibrated client-side vulnerability candidates. Same-origin credentials are never forwarded across
origins, values are masked by default, and no credential validation or third-party submission
occurs. Link review includes filtering, resolved relative URLs, and safe Repeater handoff. Build
with `./gradlew clean test jar`, then load the resulting JAR as a Java extension.

## License

MIT. See [LICENSE](LICENSE). Runtime dependency notices are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
