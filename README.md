# Ijroda Refactored

Bu papka monolit `ijroda_v4_fixed.html` faylidan ajratilgan statik loyiha variantidir.

## Tuzilma

- `index.html` ? minimal HTML skelet.
- `css/main.css` ? umumiy dizayn stillari.
- `components/app-shell.html` ? layout, auth ekranlari va panel placeholderlari.
- `components/panels/*.html` ? har bir interfeys bo'limi alohida faylda.
- `js/bootstrap.js` ? komponentlarni yuklab, dastur kodini ishga tushiradi.
- `js/app.js` ? asosiy Firebase va biznes logika.
- `js/firebase/config.js` ? Firebase sozlamalari.
- `js/data/ijro-default-data.js` ? sektorlar va xodim/lavozim profillari default bazasi.
- `js/ui/*.js` ? drag/drop va klaviatura shortcutlari.

## Ishga tushirish

Eng oson yo'l:

```text
start_ijroda.bat
```

Shu faylni ikki marta bosing. U lokal serverni yoqadi va saytni brauzerda ochadi.

Qo'lda ishga tushirish:

```bash
python -m http.server 5177
```

Keyin brauzerda `http://127.0.0.1:5177` ni oching.

Muhim: `index.html`ni to'g'ridan-to'g'ri ikki marta bosib `file://` orqali ochmang. Komponentlar `fetch()` orqali yuklanadi, shuning uchun lokal server kerak.

Ajratilgan panel soni: 19.
