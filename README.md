# 🍽 Restoran Tətbiqi — Qurulum Təlimatı

## Tətbiqin Xüsusiyyətləri
- 🏠 Ana səhifə (restoran haqqında məlumat)
- 📖 Menyu səhifəsi (kateqoriyalara görə filter)
- 🛒 Onlayn sifariş (səbət sistemi)
- 📅 Masa rezervasiyası
- 🔐 Admin paneli:
  - Dashboard (statistika)
  - Sifarişləri idarə et (status dəyiş)
  - Rezervasiyaları idarə et
  - Menyu məhsulu əlavə/sil
  - Restoran məlumatlarını yenilə

---

## Qurulum (İlk dəfə)

### 1. Python yükləyin
https://www.python.org/downloads/ — 3.10 və ya yuxarı versiya

### 2. Bu qovluqda terminal/cmd açın

### 3. Flask yükləyin
```
pip install flask
```

### 4. Tətbiqi işə salın
```
python app.py
```

### 5. Brauzerdə açın
```
http://localhost:5000
```

---

## Admin Paneli Girişi
- **URL:** http://localhost:5000/admin
- **Şifrə:** `admin123`
- ⚠️ İlk girişdən sonra şifrəni dəyin!

---

## Qovluq Strukturu
```
restaurant/
├── app.py              ← Əsas Python faylı
├── requirements.txt    ← Lazımi paketlər
├── data/               ← Avtomatik yaradılır
│   ├── menu.json       ← Menyu məlumatları
│   ├── orders.json     ← Sifarişlər
│   ├── reservations.json ← Rezervasiyalar
│   └── settings.json   ← Restoran parametrləri
└── templates/          ← HTML səhifələr
    ├── base.html
    ├── index.html
    ├── menu.html
    ├── order.html
    ├── reservation.html
    ├── admin_login.html
    ├── admin_dashboard.html
    ├── admin_orders.html
    ├── admin_reservations.html
    ├── admin_menu.html
    └── admin_settings.html
```

---

## Məlumatlar Harada Saxlanılır?
Bütün məlumatlar `data/` qovluğundakı JSON fayllarında saxlanılır.
Silmək istəmirsinizsə bu faylları ehtiyat nüsxə kimi saxlayın.

---

## Növbəti Addımlar (İstəyə görə)
- 📱 Mobil app üçün Flutter
- 💳 Online ödəniş (Stripe)
- 📧 E-mail bildirişlər
- 🗄️ Verilənlər bazası (SQLite/PostgreSQL)
