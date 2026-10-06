# راهنمای گام‌به‌گام ساخت و اجرای FoxyVPN روی ویندوز ۱۱

## وضعیت فعلی پروژه (صادقانه)
- ✅ موتور اتصال به Firefox VPN (FxA + Guardian + ProxyPass + HTTP/2 CONNECT) پیاده‌سازی و تست شده است.
- ✅ باینری `foxyvpn-proxy.exe` (پراکسی SOCKS5 محلی) همین امروز قابل استفاده است.
- ⚠️ لایه VPN سیستمی کامل (Wintun + Netstack + سرویس ویندوز + فایروال) نوشته و cross-compile شده،
  اما هنوز روی یک ویندوز ۱۱ واقعی اجرا و تأیید نشده است (PENDING REAL WINDOWS 11 HOST).

---

## مرحله ۱ — نصب پیش‌نیازها (روی ویندوز)
1. **Git for Windows**: https://git-scm.com/download/win → نصب با تنظیمات پیش‌فرض.
2. **Go 1.25 یا جدیدتر**: https://go.dev/dl/ → فایل `go1.25.x.windows-amd64.msi` را دانلود و نصب کنید.
3. PowerShell را باز کنید و بررسی کنید:
   ```powershell
   git --version
   go version
   ```
   اگر `go` شناخته نشد، PowerShell را ببندید و دوباره باز کنید.

## مرحله ۲ — دریافت کد
```powershell
cd $env:USERPROFILE
git clone <آدرس ریپازیتوری شما> foxyvpn
cd foxyvpn
```
(اگر کد را به‌صورت ZIP دارید، آن را در `C:\foxyvpn` استخراج کنید و `cd C:\foxyvpn` بزنید.)

## مرحله ۳ — بیلد
```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-windows.ps1
```
خروجی در پوشه `out\` قرار می‌گیرد: `out\foxyvpn-proxy.exe`.

اگر موقع دانلود ماژول‌های Go خطای شبکه دادید (فیلترینگ)، قبلش متغیر محیطی پراکسی را ست کنید:
```powershell
$env:HTTPS_PROXY="http://127.0.0.1:PORT"
go mod download
```

## مرحله ۴ — لاگین و بررسی اکانت
> نیاز به اکانت Firefox با اشتراک فعال **Mozilla VPN** دارد.

```powershell
.\out\foxyvpn-proxy.exe -print-info
```
- ایمیل و رمز Firefox Accounts وارد کنید.
- اگر کد تأیید به ایمیل ارسال شد، کد ۶ رقمی را در ترمینال وارد کنید.
- در صورت موفقیت، لیست سرورها و اطلاعات سهمیه نمایش داده می‌شود. توکن‌ها در
  `C:\Users\<نام شما>\.firefox-vpn-tokens.json` ذخیره می‌شوند (دفعه بعد لاگین لازم نیست).

## مرحله ۵ — اجرای VPN (حالت SOCKS5 — تنها مسیر کاملاً تست‌شده)
```powershell
# انتخاب کشور (مثلاً آلمان):
.\out\foxyvpn-proxy.exe -country DE

# یا شهر/سرور خاص با host:port:
.\out\foxyvpn-proxy.exe -proxy 154.59.120.13:443

# گزینه‌های مفید:
#   -h3            تلاش برای HTTP/3 (QUIC)؛ در صورت عدم موفقیت خودکار به HTTP/2 برمی‌گردد
#   -verbose       لاگ جزئیات هر اتصال
#   -login         لاگین اجباری تازه
#   -status-file status.json   سلامت زمان اجرا
```
برنامه پیام `SOCKS5 proxy started listen=127.0.0.1:1080 ...` و سپس
`exit verified ip=... country_code=DE ...` نمایش می‌دهد — یعنی ترافیک از IP خروجی سرور Mozilla خارج می‌شود.

## مرحله ۶ — وصل کردن مرورگر/برنامه‌ها به پراکسی
### Firefox
Settings → Network Settings → Manual proxy configuration:
- SOCKS Host: `127.0.0.1` Port: `1080`، نوع: **SOCKS5**
- تیک **Remote DNS** را بزنید (جلوگیری از نشت DNS).

### Chrome/Edge
Chrome با فلگ:
```powershell
& "C:\Program Files\Google\Chrome\Application\chrome.exe" --proxy-server="socks5://127.0.0.1:1080"
```

### curl / PowerShell
```powershell
curl.exe --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
Invoke-WebRequest -Proxy http://127.0.0.1:1080 https://ifconfig.co   # (برای SOCKS از curl.exe استفاده کنید)
```
در خروجی باید `ip=` مربوط به سرور انتخابی Mozilla و `loc=DE` (یا کشور مقصد) باشد.

## توقف
در همان پنجره PowerShell کلیدهای `Ctrl+C`.

---

## عیب‌یابی
| مشکل | راه‌حل |
|---|---|
| `program 'go' not found` | نصب Go؛ سپس PowerShell را دوباره باز کنید. |
| خطای execution policy | دستور بالا با `-ExecutionPolicy Bypass` را اجرا کنید. |
| `no subscription / entitlement error` | اشتراک Mozilla VPN روی همین اکانت باید فعال باشد. |
| کد تأیید ایمیل نمی‌رسد | پوشه Spam؛ یا `-login` مجدد. |
| Token منقضی/401 | `-login` برای لاگین تازه. |
| دسترسی به FxA مسدود است | `-api-proxy http://127.0.0.1:PORT` برای عبور API از پراکسی دیگر. |
| پورت 1080 اشغال است | `-listen 127.0.0.1:10808` |

## محدودیت‌های واقعی نسخه فعلی
- UDP از طریق تانل پشتیبانی نمی‌شود (محدودیت ترنسپورت Firefox VPN = TCP stream).
- این ابزار «پراکسی محلی» است، نه VPN سطح سیستم؛ برای VPN کامل (بدون تنظیم پراکسی در برنامه‌ها)
  به لایه Wintun/Netstack نیاز است که کدنویسی شده ولی منتظر تست روی ویندوز واقعی است.
- IPv6 در حالت پراکسی بدون مدیریت جداگانه است؛ برای نشت‌ستیزی کامل روی سیستم، همان لایه ویندوزی لازم است.
