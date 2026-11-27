<div align="center">
  <img src="EGOicon.png" alt="EGO Suite Logo" width="110" />
  <h1>EGO Suite</h1>
  <p><strong>Unified Open-Source AppSec &amp; Vulnerability Auditing Orchestrator for Linux</strong></p>
  <p>منصة أمان محلية موحدة تجمع أشهر أدوات الفحص الأمني مفتوحة المصدر في مكان واحد — تدعم فحص المواقع الحية (URL)، المشاريع المحلية (Local Path)، ومستودعات GitHub مباشرة، مع تقارير مجمعة وتتبع إعادة الاختبار (Re-test).</p>
</div>

---

## المميزات الرئيسية (Key Features)

- **ثلاثة أوضاع للفحص في واجهة واحدة:**
  - **فحص الروابط الحية (`URL / DAST`):** للمواقع المستضافة على الإنترنت بدون الحاجة لنسخة محلية.
  - **فحص المشاريع المحلية (`Local / SAST + SCA + Secrets + IaC`):** تحليل الكود المصدري والمكتبات والأسرار المسربة وحاويات Docker على جهازك.
  - **ربط حساب GitHub (`GitHub Integration`):** اختيار أي مستودع (عام أو خاص) من حسابك ليتم سحبه سطحياً (`shallow clone`) وفحصه تلقائياً دون تخزين التوكن في `.git/config`.
- **تثبيت ذاتي ومحمول على Linux (`ego-setup.sh`):**
  - ينشئ بيئة معزولة بالكامل (`.venv/`, `.node_tools/`, `bin/`, `data/`) داخل مجلد المشروع، مما يجعل نقله وتحديثه بين عدة أجهزة Linux أمراً فورياً.
- **شريط تقدم مباشر ووقت متبقي (`Live Progress & ETA`):**
  - متابعة حية لكل أداة قيد التشغيل، النسبة المئوية، الوقت المنقضي، والوقت المتبقي التقريبي.
- **توحيد النتائج وإعادة الاختبار (`Unified Schema & Re-test Diffing`):**
  - توحيد مخرجات `SARIF` و`JSON` في قاعدة بيانات SQLite مع بصمة فريدة (`fingerprint`) لكل ثغرة، ومقارنة تلقائية عند إعادة الاختبار لإظهار الثغرات المحلولة (`Fixed`) والجديدة (`New`).
- **تقارير مجمعة واحترافية:**
  - تصدير فوري بصيغتي **HTML** و**Markdown**، مع إمكانية إدارة حالة كل ثغرة أو حذف التقارير القديمة.
- **دعم الذكاء الاصطناعي والـ AI Skills (`AI-Ready CLI & Skill`):**
  - يتضمن ملف Skill جاهز ([skills/ego-suite/SKILL.md](skills/ego-suite/SKILL.md)) وأوامر CLI مهيكلة (`ego scan --wait --json` و`/api/scans/{id}/ai-report`) تتيح لوكيل الذكاء الاصطناعي تشغيل الفحوصات بنفسه، قراءة التقارير المهيكلة، إصلاح الثغرات في الكود، وإعادة الاختبار تلقائياً.
- **واجهة مميزة (`Yellow & Black Theme`):**
  - واجهة ويب عربية (RTL) عالية التباين باللونين الأصفر والأسود، بالإضافة إلى اختصار سطح مكتب وأيقونة في قائمة تطبيقات Linux.

---

## الأدوات المدمجة (20 أداة آمنة ومفتوحة المصدر)

| الفئة | الأدوات | الوظيفة |
| :--- | :--- | :--- |
| **DAST (روابط حية)** | `ego-http-audit` (مدمج), `OWASP ZAP`, `Nuclei`, `testssl.sh`, `Nikto`, `Nmap`, `Wapiti`, `httpx` | فحص ترويسات الأمان، شهادات SSL/TLS، المنافذ المفتوحة، وثغرات الويب الشائعة |
| **SAST (تحليل الكود)** | `Semgrep`, `Bandit`, `ESLint Security`, `Bearer CLI`, `SonarScanner` | اكتشاف الثغرات والأنماط البرمجية غير الآمنة في الكود المصدري |
| **SCA (المكتبات)** | `Trivy`, `OSV-Scanner`, `Retire.js`, `pip-audit & npm audit` | فحص الاعتماديات والمكتبات لاكتشاف الثغرات المعروفة (CVEs) |
| **Secrets (الأسرار)** | `Gitleaks`, `TruffleHog` | كشف مفاتيح API وكلمات المرور المسربة في الكود وتاريخ Git |
| **IaC (البنية التحتية)** | `Checkov` | فحص ملفات `Dockerfile`, `Terraform`, `Kubernetes`, وملفات CI/CD |

---

## التثبيت والتشغيل على Linux (Quick Start)

### 1. استنساخ المشروع وتشغيل المثبت التلقائي
```bash
git clone https://github.com/richnessagencyteam-code/ego-suite.git
cd ego-suite
chmod +x ego ego-setup.sh
./ego-setup.sh
```
سيقوم `ego-setup.sh` تلقائياً بإنشاء البيئة المعزولة، تثبيت أدوات Python وNode.js، تنزيل الملفات التنفيذية للأدوات في `bin/`، وإضافة الأمر العالمي `ego` وأيقونة التطبيق في قائمة النظام.

*(اختياري) لتفعيل أداتي Docker (`owasp-zap` و`sonarqube-scanner`):*
```bash
sudo docker pull ghcr.io/zaproxy/zaproxy:stable
sudo docker pull sonarqube:community
```

### 2. تشغيل البرنامج
من أي مجلد في الطرفية:
```bash
ego
```
أو لتشغيله في الخلفية وفتح المتصفح تلقائياً:
```bash
ego --open
```
ثم افتح المتصفح على: `http://127.0.0.1:8787` (أو ابحث عن **EGO Suite** في قائمة تطبيقات Linux).

---

## التحديث على باقي أجهزتك (Multi-Machine Sync)
بفضل فصل ملفات البيانات (`data/`) والبيئة المحلية (`.venv/`, `bin/`) عن الكود عبر `.gitignore`، يمكنك تحديث أي جهاز بسطر واحد دون فقدان تقاريرك أو إعداداتك:
```bash
ego update
```

---

## التشغيل عبر الذكاء الاصطناعي (AI Agent & Skill Mode)
يمكن لأي وكيل ذكاء اصطناعي (مثل Antigravity) استخدام المهارة المدمجة `skills/ego-suite/SKILL.md` لتشغيل الفحوصات واستلام تقارير JSON سهلة القراءة:
```bash
# فحص رابط أو مشروع محلي والانتظار حتى صدور التقرير المهيكل للـ AI
ego scan --name "My App" --path "/path/to/project" --wait --json

# أو جلب تقرير فحص سابق بصيغة AI-JSON
ego report 1 --json
```

---

## هيكل المشروع (Project Structure)

```text
ego-suite/
├── ego                  # المشغّل العالمي وأمر التحديث (ego / ego --open / ego update)
├── ego-setup.sh         # المثبت التلقائي المحمول لنظام Linux
├── requirements.txt     # اعتماديات الخادم (FastAPI, Uvicorn, Pydantic)
├── selected-tools.json  # قائمة الأدوات المختارة
├── tools-catalog.html   # دليل الأدوات التفاعلي المستقل
├── ego_suite/
│   ├── server.py        # خادم FastAPI وواجهات API
│   ├── orchestrator.py  # محرك إدارة الفحوصات وتتبع التقدم والـ ETA
│   ├── adapters.py      # محولات تشغيل الأدوات والفحص المدمج
│   ├── normalizer.py    # توحيد مخرجات SARIF / JSON
│   ├── github_client.py # ربط GitHub وسحب المستودعات بأمان
│   ├── reporter.py      # مولد تقارير HTML و Markdown
│   └── db.py            # قاعدة بيانات SQLite ومحرك مقارنة Re-test
└── web/
    └── index.html       # واجهة المستخدم (Yellow & Black Dashboard)
```

---

## الاستخدام المسؤول (Responsible Use)
هذا المشروع مصمم لأغراض **الأمن الدفاعي، مراجعة الكود، واختبار المواقع والتطبيقات التي تملكها أو تملك تصريحاً صريحاً بفحصها فقط**. المطور غير مسؤول عن أي استخدام غير مصرح به.

---

## الرخصة (License)
مرخص تحت رخصة [MIT](LICENSE). الأدوات الخارجية يتم استدعاؤها كأدوات مستقلة وتخضع كل أداة لرخصتها الرسمية المفتوحة المصدر.

