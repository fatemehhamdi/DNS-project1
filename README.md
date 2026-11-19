# راهنمای کامل اجرای تست‌های PatchVal


> این راهنما بر اساس فایل‌های واقعی `Makefile`، `run_all.sh`، `run_unseen.sh`، `scripts/run_in_docker.sh`، `Dockerfile`، `patchval/cli.py` و تست‌های همین نسخه تهیه شده است.

## ۱. چه تست‌هایی داریم؟

| بخش | فرمان | چه چیزی بررسی می‌شود؟ |
|---|---|---|
| Unit Test | `make unit` | منطق ماژول‌های Python، بدون نیاز به اجرای هدف‌های آسیب‌پذیر در اکثر موارد |
| Integration Test | `make integration` | همکاری Build، Runner، Crash، Pipeline، Regression و Reproducer روی برنامه‌های واقعی |
| کل تست‌های Python | `make test` | هر دو گروه Unit و Integration؛ جایگزین اجرای سناریوهای Shell **نیست** |
| ۱۲ سناریوی اصلی | `./run_all.sh` | وصله‌های Correct، Incomplete و Regression برای سه Target و حالت‌های ورودی مختلف |
| ۶ وصله آزمایشی | `./run_unseen.sh` | اعمال فایل‌های Diff جدید، خطای امنیتی جدید، Timeout، رد ورودی و خطای Build |

**برای پوشش کامل:** `make test` + `./run_all.sh` + `./run_unseen.sh` را اجرا کنید؛ یا معادل ایزوله آن‌ها را در Docker انجام دهید. تعداد آزمون‌های `pytest` با نسخه فایل‌های تست تغییر می‌کند؛ عدد دقیق را خروجی آن نشان می‌دهد.

### نکته ایمنی خیلی مهم

بعضی Targetها **عمداً آسیب‌پذیر** هستند. تست‌های Integration و سناریوهای اصلی را **روی میزبان بدون ایزوله‌سازی اجرا نکنید**. روش پیشنهادی این راهنما Docker است. اگر اجرای محلی را انتخاب می‌کنید، پیش از شروع مطمئن شوید `bwrap` با سطح `full` واقعاً کار می‌کند. گزینه `--allow-no-isolation` برای گزارش رسمی یا CI مناسب نیست.

---

## ۲. ورود به پوشه اصلی پروژه




```bash
pwd
ls -la
ls patchval/cli.py Makefile run_all.sh run_unseen.sh Dockerfile
```

همه فرمان‌های بعدی را، مگر آنکه خلافش ذکر شده باشد، **از ریشه** اجرا کنید.

---

## ۳. روش پیشنهادی: اجرای تمام تست‌ها در Docker

این روش وابستگی مستقیم به فعال‌بودن Namespace روی لینوکس میزبان را کمتر می‌کند؛ زیرا کانتینر خودش مرز ایزوله‌سازی است.

### ۳.۱. پیش‌نیاز Docker

Docker Engine را روی لینوکس نصب و فعال کنید؛ سپس مطمئن شوید این دستورها موفق‌اند:

```bash
docker --version
docker info
```

اگر `docker info` خطای دسترسی به Daemon داد، Docker را بر اساس راهنمای سیستم‌عامل راه‌اندازی کنید. عضویت در گروه `docker` سطح دسترسی بالایی به میزبان می‌دهد؛ تغییر دسترسی‌ها را آگاهانه انجام دهید.

### ۳.۲. اجرای یک سناریو داخل Docker

این اسکریپت **همراه خود پروژه** است:

```bash
scripts/run_in_docker.sh -c targets/csvsum/config.correct.yaml
```

کار اسکریپت:

1. Image با نام `patchval` را می‌سازد.
2. کانتینر را با شبکه قطع‌شده، محدودیت CPU/حافظه/فرایندها و فایل‌سیستم فقط‌خواندنی اجرا می‌کند.
3. نتیجه سناریوی `csvsum_correct` را در این مسیرها ذخیره می‌کند:

```text
docker_out/report.json
docker_out/artifacts/
docker_registry/
```

**توجه:** اسکریپت بالا فقط **یک سناریو** را اجرا می‌کند و ممکن است `docker_out/report.json` در اجرای بعدی بازنویسی شود؛ برای تمام سناریوها از بخش بعدی استفاده کنید.

### ۳.۳. اجرای همه تست‌ها با یک فرمان Docker

از ریشه پروژه این دستورات را اجرا کنید:

```bash
docker build -t patchval .
mkdir -p docker_out docker_registry

docker run --rm \
  --user "$(id -u):$(id -g)" \
  --network none \
  --memory 2g --memory-swap 2g --cpus 2 --pids-limit 512 \
  --read-only --tmpfs /tmp:rw,exec,size=1g \
  --security-opt no-new-privileges \
  -e HOME=/tmp -e PATCHVAL_REGISTRY_DIR=/registry \
  -v "$PWD/docker_out:/out" \
  -v "$PWD/docker_registry:/registry" \
  --entrypoint /bin/bash patchval -lc '
    set -e
    echo "=== 1/3 Python unit + integration ==="
    python3 -m pytest tests -q -o cache_dir=/tmp/pytest-cache
    echo "=== 2/3 Delivered scenarios ==="
    OUT_ROOT=/out/runs REPORTS=/out/reports ./run_all.sh
    echo "=== 3/3 Unseen patches ==="
    OUT_ROOT=/out/unseen ./run_unseen.sh
  '
```

این فرمان به‌ترتیب **تست‌های Python، ۱۲ سناریوی اصلی و ۶ وصله آزمایشی** را اجرا می‌کند. `set -e` باعث می‌شود اگر یکی از سه مرحله شکست خورد، اجرای مراحل بعدی متوقف شود؛ برای دیدن نتیجه همه مرحله‌ها در صورت شکست یکی از آن‌ها، آن‌ها را جداگانه اجرا کنید.

خروجی‌ها روی سیستم میزبان باقی می‌مانند:

```text
docker_out/
├── runs/           # ۱۲ سناریوی اصلی: Build، لاگ، Reproducer و report.json
├── reports/        # کپی گزارش JSON و متنی سناریوهای اصلی
└── unseen/         # ۶ وصله آزمایشی و گزارش‌های آن‌ها

docker_registry/     # کپی پایدار Regression Suiteها؛ جدا از سورس
```

این فرمان با تنظیمات Docker پروژه هماهنگ است؛ **موفقیت واقعی اجرای آن روی سیستم شما باید از خروجی Docker تأیید شود** و از پیش تضمین نشده است.

---

## ۴. روش جایگزین: اجرای محلی با Bubblewrap

این روش را فقط وقتی انتخاب کنید که `bwrap` به‌درستی کار می‌کند.

### ۴.۱. نصب پیش‌نیازها در Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y \
  python3 python3-venv python3-pip \
  gcc clang make patch git binutils bubblewrap util-linux
```

در Fedora یا توزیع دیگر، بسته‌های معادل را با Package Manager خود نصب کنید.

### ۴.۲. آماده‌سازی محیط Python

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m patchval --help
```

در ترمینال‌های بعدی، قبل از اجرای تست‌ها دوباره `source .venv/bin/activate` را بزنید.

### ۴.۳. بررسی واقعی ایزوله‌سازی

```bash
python - <<'PY'
from patchval.sandbox import select
s = select('auto')
print('backend:', s.backend)
print('level:', s.level)
print('reason:', s.reason)
if s.level != 'full':
    print('WARNING: برای اجرای تست‌های آسیب‌پذیر، مسیر Docker پیشنهاد می‌شود.')
PY
```

خروجی مطلوب برای اجرای محلی:

```text
backend: bwrap
level: full
```

اگر نتیجه `none`، `rlimits-only` یا `partial` بود، برای اجرای کامل **به Docker برگردید**. بعضی نصب‌های Ubuntu 24.04 استفاده از User Namespace را محدود می‌کنند؛ تغییر تنظیمات امنیتی سراسری سیستم را صرفاً برای پاس‌شدن تست‌ها انجام ندهید.

### ۴.۴. اجرای Unit Test؛ مستقل و سریع

```bash
make unit
```

یا:

```bash
python -m pytest tests/test_unit.py -q
```

### ۴.۵. اجرای Integration Test

**فقط بعد از تأیید `bwrap` با سطح `full`:**

```bash
make integration
```

یا:

```bash
python -m pytest tests/test_integration.py -q
```

اگر پیام `skipped` دیدید، به‌ویژه به‌علت نبود Sandbox، این **تأیید موفقیت تست‌های اجرایی نیست**؛ علت Skip را برطرف کنید یا Docker را انتخاب کنید.

### ۴.۶. اجرای یکجای تست‌های Python

```bash
make test
```

این دستور معادل `python3 -m pytest tests -q` است، اما **سناریوهای `run_all.sh` و `run_unseen.sh` را اجرا نمی‌کند**.

### ۴.۷. اجرای ۱۲ سناریوی اصلی و نگه‌داشتن تمام خروجی‌ها

برای اینکه تست‌ها پوشه‌های رگرسیون موجود در سورس را ناخواسته تغییر ندهند، Registry را در یک پوشه خروجی مستقل قرار دهید:

```bash
mkdir -p _runs/main _runs/unseen _runs/regression_registry reports
export PATCHVAL_REGISTRY_DIR="$PWD/_runs/regression_registry"

OUT_ROOT="$PWD/_runs/main" \
REPORTS="$PWD/reports" \
EXTRA_ARGS="--sandbox bwrap" \
./run_all.sh
```

نتیجه مورد انتظار در انتهای خروجی:

```text
PASS=12 FAIL=0
```

**معنی این نتیجه:** هر سناریو همان کد خروج مورد انتظارش را تولید کرده است؛ این الزاماً به معنی کد `0` برای تک‌تک سناریوها نیست. برای وصله ناقص، کد `10` و برای پسرفت عملکردی، کد `20` نتیجه درستِ آن سناریو است.

### ۴.۸. اجرای ۶ وصله آزمایشی

```bash
OUT_ROOT="$PWD/_runs/unseen" \
EXTRA_ARGS="--sandbox bwrap" \
./run_unseen.sh
```

نتیجه مورد انتظار:

```text
PASS=6 FAIL=0
```

این شش سناریو از فایل `unseen_patches/expected.tsv` خوانده می‌شوند. گزینه‌های مختلفی مثل `NEW_ISSUE`، Timeout و خطای Build را می‌آزمایند.

### ۴.۹. اجرای یک سناریوی خاص و دیدن Exit Code

```bash
python -m patchval \
  -c targets/csvsum/config.correct.yaml \
  --sandbox bwrap --require-isolation \
  --registry-dir "$PWD/_runs/regression_registry" \
  --work "$PWD/_runs/single" \
  --json "$PWD/_runs/single/report.json"

echo "exit code: $?"
```

برای جایگزین‌کردن نسخه وصله‌شده با یک فایل Diff موجود:

```bash
python -m patchval \
  -c targets/csvsum/config.correct.yaml \
  --patch unseen_patches/csvsum_alt_fix_skip_row.diff \
  --sandbox bwrap --require-isolation \
  --no-update-regression \
  --work "$PWD/_runs/one_patch" \
  --json "$PWD/_runs/one_patch/report.json"

echo "exit code: $?"
```

فرمان `--patch` وصله را روی **کپی Base** اعمال می‌کند و خود Base را تغییر نمی‌دهد. اگر Patch از فایل‌هایی با پیشوند `a/` و `b/` استفاده می‌کند، مقدار پیش‌فرض `--strip 1` مناسب است؛ در غیر این صورت بر اساس قالب فایل، `--strip N` را تغییر دهید.

---

## ۵. Exit Codeها را چگونه بخوانیم؟

| کد | نتیجه | تفسیر |
|---:|---|---|
| `0` | `PASS` | خطای پایه پایدار بازتولید و روی Patch در محدوده تست‌ها مشاهده نشده؛ آزمون‌های الزامی موفق‌اند |
| `10` | `VULN_OR_SECURITY` | آسیب‌پذیری باقی مانده، وصله ناقص است یا خطای امنیتی تازه پیدا شده |
| `20` | `FUNC_REGRESSION` | ورودی معتبری که روی Base درست بوده، روی Patched خراب شده |
| `30` | `BUILD_OR_CONFIG_ERROR` | خطای Build/Config/زیرساخت؛ از جمله نبود Sandbox الزامی |
| `40` | `INCONCLUSIVE` | شواهد ناکافی، Timeout یا بازپخش ناپایدار |

در یک ارزیابی واحد، اولویت: `30 > 10 > 20 > 40 > 0` است.

در سناریوهای آزمایشی، **کد ۱۰ یا ۲۰ شکست ابزار نیست**؛ اسکریپت نتیجه واقعی را با عدد صحیح همان سناریو مقایسه می‌کند.

---

## ۶. گزارش‌ها و لاگ‌ها کجا ذخیره می‌شوند؟

### اگر فرمان‌های محلی این راهنما را اجرا کرده‌اید

```text
_runs/
├── main/<scenario>/report.json
├── main/<scenario>/artifacts/patch.diff
├── main/<scenario>/artifacts/logs/<test-id>/
│   ├── base-release.stdout
│   ├── base-release.stderr
│   ├── base-sanitized.stdout
│   ├── base-sanitized.stderr
│   ├── patched-release.stdout
│   ├── patched-release.stderr
│   ├── patched-sanitized.stdout
│   └── patched-sanitized.stderr
├── main/<scenario>/artifacts/minimized/       # در صورت وجود Crash قابل کوچک‌سازی
├── main/<scenario>/artifacts/reproducers/     # در صورت ایجاد بسته بازتولید
├── unseen/<scenario>/report.json
└── regression_registry/
reports/
├── <scenario>.report.json
└── <scenario>.report.txt
```

پوشه‌های `minimized` و `reproducers` **شرطی** هستند؛ در هر اجرای ناموفق یا بدون Crash لزوماً ساخته نمی‌شوند.

**نکته:** اگر `OUT_ROOT` ندهید، اسکریپت‌های Shell خروجی را در پوشه‌های موقت `/tmp/patchval_runs.*` و `/tmp/patchval_unseen.*` می‌نویسند. اگر `REPORTS` ندهید، کپی گزارش‌ها در `reports/` ساخته نمی‌شود.

### مشاهده تمام نتیجه‌های اصلی در یک جدول

```bash
python - <<'PY'
import json
from pathlib import Path
for p in sorted(Path('_runs/main').glob('*/report.json')):
    d = json.loads(p.read_text())
    v = d.get('verdict', {})
    iso = d.get('isolation', {})
    print(f"{p.parent.name:35} exit={v.get('exit_code')} "
          f"complete={v.get('analysis_complete')} "
          f"sandbox={iso.get('backend')} [{iso.get('level')}]")
PY
```

برای خروجی Docker، در اسکریپت بالا `_runs/main` را به `docker_out/runs` تغییر دهید.

### خواندن JSON یک سناریو

```bash
python -m json.tool _runs/main/csvsum_correct/report.json | less
```

اگر نام پوشه دقیق سناریو متفاوت بود، آن را با `find _runs/main -name report.json` پیدا کنید. گزارش حاوی `verdict`، چهار Build، `executions`، `findings`، `hardening` و `regression` است.

### دیدن لیست همه گزارش‌ها و بسته‌های بازتولید

```bash
find _runs/main _runs/unseen -name report.json -print
find _runs/main -name manifest.json -print
find _runs/main -name '*.stderr' -print | head -30
```

**اسکریپت‌های `replay.sh` داخل بسته‌های بازتولید ممکن است برنامه آسیب‌پذیر اجرا کنند. آن‌ها را روی میزبان، خارج از محیط ایزوله، اجرا نکنید.**

---

## ۷. اجرای خودکار CI در GitHub و GitLab

فایل‌های اصلی از قبل در پروژه وجود دارند:

```text
.github/workflows/patchval.yml
.gitlab-ci.yml
```

**GitHub Actions:** مخزن را طوری Push کنید که `.github/workflows/patchval.yml` مستقیماً در ریشه مخزن باشد. از تب **Actions** اجرای Workflow با نام `patchval` را بررسی کنید. Jobهای `self-test` و `scenarios` باید موفق شوند. Job `validate-patch` برای اجرای دستی (`workflow_dispatch`) است و می‌تواند یک فایل Diff را بررسی کند.

**GitLab CI:** فایل `.gitlab-ci.yml` باید در ریشه مخزن باشد. Stageهای `self-test` و `scenarios` تعریف شده‌اند.

وجود این فایل‌ها به‌تنهایی ثابت نمی‌کند CI روی سرویس میزبانی‌شده موفق شده است؛ نتیجه Jobها و Artifactهای آن‌ها را نیز بررسی و ذخیره کنید.

---

## ۸. خطاهای رایج

| مشکل | علت محتمل و راه‌حل |
|---|---|
| `No module named yaml` | محیط Python درست فعال نشده یا `pip install -r requirements.txt` اجرا نشده است |
| `No module named pytest` | بسته `pytest` را در همان محیط Python نصب کنید |
| `bwrap ... Permission denied` | User Namespace یا سیاست امنیتی سیستم اجازه نمی‌دهد؛ Docker را ترجیح دهید |
| `exit 30` هنگام همه سناریوها | ممکن است Sandbox قابل استفاده نباشد یا Build/Config مشکل داشته باشد؛ stderr و JSON را بررسی کنید |
| `skipped` در pytest | Integration Test واقعاً اجرا نشده؛ دلیل Skip را بخوانید |
| `PASS=0 FAIL=12` | به‌احتمال زیاد زیرساخت اجرا آماده نیست؛ گزارش اولین سناریو را باز کنید |
| `docker: permission denied` | دسترسی به Docker Daemon موجود نیست؛ `docker info` را بررسی کنید |
| `No space left on device` | فضای خروجی یا tmpfs کانتینر کافی نیست؛ فضای مجاز را با احتیاط افزایش دهید |
| `report.json` تولید نشد | بعضی خطاهای اولیه Config در این نسخه پیش از مرحله گزارش‌دهی رخ می‌دهند؛ stderr را بخوانید |
| `make test` موفق شد اما `run_all.sh` شکست خورد | طبیعی است که دو مسیر پوشش یکسانی نداشته باشند؛ تست‌های Shell را مستقل عیب‌یابی کنید |

---

## ۹. پاک‌سازی و نگهداری خروجی‌ها

دستور موجود در پروژه:

```bash
make clean
```

در این نسخه، این دستور `_runs/`، `docker_out/`، `reports/`، کش pytest و بعضی `__pycache__`ها را حذف می‌کند. **همه مسیرهای موقت** و **همه Cacheها** را پوشش نمی‌دهد؛ همچنین `docker_registry/` و مسیرهای `/tmp/patchval_*` را پاک نمی‌کند.

قبل از `make clean`، اگر نتایج برای تحویل به استاد لازم‌اند، از `report.json`، `logs/`، `reproducers/` و شواهد موفقیت CI نسخه پشتیبان بگیرید.

`targets/*/regression/` را به‌طور کامل حذف نکنید: این مسیر علاوه بر داده‌های Regression، در بعضی Targetها **سورس نسخه دارای پسرفت عملکردی** را هم نگه می‌دارد.

---

## ۱۰. چک‌لیست اجرای کامل قبل از تحویل

- [ ] در ریشه درست پروژه هستم.
- [ ] Python، کامپایلرها، PyYAML و pytest در دسترس‌اند.
- [ ] آزمایش‌های آسیب‌پذیر در Docker یا یک Sandbox با سطح `full` اجرا شده‌اند.
- [ ] Unit Test و Integration Test اجرا شده‌اند؛ Skip غیرمنتظره نداریم.
- [ ] خروجی `run_all.sh` برابر `PASS=12 FAIL=0` است.
- [ ] خروجی `run_unseen.sh` برابر `PASS=6 FAIL=0` است.
- [ ] گزارش‌های JSON برای همه سناریوها ذخیره شده‌اند.
- [ ] برای Verdictهای `0`، وضعیت `analysis_complete=true` و ایزوله‌سازی مناسب است.
- [ ] لاگ‌های `stdout` و `stderr` و بسته‌های Reproducer موجود و قابل بازرسی هستند.
- [ ] Registry تست‌های رگرسیون و نتایج CI را برای تحویل نگه داشته‌ام.
- [ ] مدارک تأیید Targetها و مشارکت اعضای گروه نیز تکمیل شده‌اند.

### کوتاه‌ترین خلاصه دستورات

**روش محلی فقط با Bubblewrap فعال و کامل:**

```bash
source .venv/bin/activate
make test
mkdir -p _runs/regression_registry
export PATCHVAL_REGISTRY_DIR="$PWD/_runs/regression_registry"
OUT_ROOT="$PWD/_runs/main" REPORTS="$PWD/reports" EXTRA_ARGS="--sandbox bwrap" ./run_all.sh
OUT_ROOT="$PWD/_runs/unseen" EXTRA_ARGS="--sandbox bwrap" ./run_unseen.sh
```

**روش Docker:** بخش ۳.۳ همین راهنما همه مراحل را در یک کانتینر محدودشده اجرا می‌کند.
