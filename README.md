# NetworkOptimizer 2.0

<div dir="rtl">

## بالعربي

برنامج لنظام Windows يختار **أفضل DNS** و**أفضل MTU** لشبكتك بالقياس الفعلي فقط، ولا يعتمد على أي افتراضات.

### التشغيل
1. ثبّت Python 3.9 أو أحدث من python.org (فعّل خيار "Add python.exe to PATH").
2. افتح **Run.bat**، وتفتح لوحة البرنامج الكاملة (نفس صفحات وتفاصيل النسخة القديمة) داخل نافذة برنامج عادية من غير متصفح (`--simple` لنافذة مبسطة، `--web` للمتصفح). اضغط «ابدأ الفحص» وهتشوف أفضل DNS وأفضل MTU بنتيجة واحدة واضحة وزر «طبّق التوصية».

البرنامج لا يحتاج أي مكتبات إضافية. يعمل كمستخدم عادي، ويطلب صلاحية المسؤول **فقط** عند تطبيق إعداد أو استعادته.

### الملفات
| الملف | الوظيفة |
|---|---|
| Run.bat | تشغيل البرنامج |
| Run_Tests.bat | تشغيل الاختبارات الآلية |
| Build_EXE.bat | بناء ملف EXE واحد (يحتاج إنترنت لتحميل PyInstaller) |
| Upload_To_GitHub.bat | رفع آمن للمشروع على GitHub من غير توكن، مع فحص للأسرار قبل الرفع |

### خطوات الاستخدام المقترحة
1. **قبل / بعد ← القياس قبل**
2. **لوحة التحكم ← اختبار كامل** (يختبر DNS أولًا ثم MTU)
3. **تطبيق التوصيات…** ← اختر ما تريد تطبيقه ← وافق على طلب صلاحية Windows
4. **قبل / بعد ← القياس بعد**: سيظهر لك إن كان هناك تحسن حقيقي أم لا

كل بياناتك (الملفات الشخصية، النسخ الاحتياطية، السجلات) محفوظة محليًا فقط في `%APPDATA%\NetworkOptimizer`.

</div>

## English

Evidence-based DNS and MTU optimization for Windows 10/11.

* **Run:** `Run.bat` (Python 3.9+, no third-party packages). Opens a native desktop window (Tkinter, no browser). The old browser dashboard is still available with `--web`.
* **Admin rights:** only requested (UAC) at the moment you apply or restore settings.
* **Data:** `%APPDATA%\NetworkOptimizer` (settings, profiles, backups, logs, CSV benchmark logs). Never uploaded.
* **How scores and decisions work:** see [SCORING.md](SCORING.md).
* **What is implemented and tested:** see [CHECKLIST.md](CHECKLIST.md).

### Layout
```
netoptimizer/
  core/dnswire.py      raw UDP DNS client (real queries)
  core/dns_bench.py    DNS benchmark + documented scoring
  core/icmp.py         DF ICMP probes (Windows IcmpSendEcho, IPv6 PMTU cache)
  core/mtu.py          binary-search MTU discovery + confidence
  core/netinfo.py      adapter discovery (PowerShell), PPPoE/VPN detection, fingerprint
  core/profiles.py     per-network profiles
  core/backup.py       never-overwrite backups
  core/apply.py        validated, elevated apply/restore
  core/compare.py      before/after with significance tests
  core/monitor.py      lightweight network change detection
  core/diagnostics.py  extra tools
  core/jobs.py         background jobs with cancellation
  app.py               orchestration
  ui/server.py         loopback-only HTTP API (per-launch token)
  ui/static/           dashboard (Arabic/English, dark/light, charts)
tests/                 60 automated tests (unittest)
tools/check_secrets.py pre-upload credential scanner
```

### Developer
```
python -m netoptimizer --no-browser --port 8765
python -m unittest discover -s . -p "test_*.py" -t . -v
```
