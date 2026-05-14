# Yuridik AI va hujjatlar tahlili moduli

Ushbu modul ijro nazorati tizimiga yuridik hujjatlarni tahlil qilish, topshiriqlarni ajratish, huquqiy asoslarni ko'rsatish, qurilish hujjatlari checklistini tekshirish, ijro riskini baholash va rasmiy hisobot matni yozish imkoniyatini qo'shadi.

## Asosiy oqim

1. Foydalanuvchi PDF, Word, rasm yoki matn yuklaydi.
2. Lokal parser hujjat turi, raqam, sana, organ, soha, masul, muddat va topshiriqlarni ajratadi.
3. Maxfiy hujjat bo'lmasa va Gemini/OpenRouter kaliti mavjud bo'lsa, AI tahlilni JSON schema bo'yicha boyitadi.
4. Manba topilmasa tizim taxmin qilmaydi va `Bazadan aniq huquqiy asos topilmadi` ogohlantirishini chiqaradi.
5. Natija `document_analysis`, `extracted_tasks`, `ai_answers` va `ai_audit_logs` kolleksiyalariga yoziladi.
6. Har bir task foydalanuvchi tasdig'idan keyin ijro nazoratiga alohida topshiriq sifatida qo'shiladi.

## RAG production arxitekturasi

Static GitHub Pages varianti demo/MVP uchun ishlaydi. Production uchun quyidagi oqim tavsiya qilinadi:

1. Rasmiy hujjatlarni Lex.uz, ichki baza yoki tasdiqlangan importdan olish.
2. PDF/Word/HTML matnini serverda ajratish.
3. Matnni modda, band, qism va ilovalarga bo'lish.
4. Metadata qo'shish: `document_type`, `number`, `date`, `issuing_body`, `sector`, `status`, `legal_force_rank`.
5. Embedding yaratish va vector databasega joylash.
6. Savolda hybrid search ishlatish: semantic search, exact keyword, hujjat raqami, sana, soha, status va legal force ranking.
7. AI javobini faqat topilgan chunklar va statusi amaldagi manbalarga asoslash.
8. Har bir javobni manbalari, confidence va audit log bilan saqlash.

## Tavsiya etilgan database schema

### `legal_documents`

- `id`
- `title`
- `document_type`
- `number`
- `date`
- `issuing_body`
- `sector`
- `status`
- `language`
- `source_url`
- `file_url`
- `legal_force_rank`
- `last_checked_at`
- `created_at`
- `updated_at`

### `legal_document_chunks`

- `id`
- `document_id`
- `chunk_text`
- `article`
- `clause`
- `page_number`
- `embedding`
- `metadata`
- `created_at`

### `document_analysis`

- `id`
- `uploaded_file_id`
- `user_id`
- `organization_id`
- `detected_type`
- `detected_number`
- `detected_date`
- `detected_sector`
- `summary`
- `extracted_tasks`
- `detected_responsibles`
- `detected_deadlines`
- `legal_basis`
- `risk_level`
- `confidence_score`
- `created_at`

### `extracted_tasks`

- `id`
- `analysis_id`
- `source_document_id`
- `source_clause`
- `title`
- `description`
- `responsible_organization`
- `responsible_person`
- `deadline`
- `priority`
- `risk_level`
- `required_documents`
- `recommended_actions`
- `status`
- `created_at`

### `ai_answers`

- `id`
- `user_id`
- `organization_id`
- `question`
- `answer`
- `sources`
- `confidence_score`
- `risk_level`
- `created_at`

### `ai_audit_logs`

- `id`
- `user_id`
- `organization_id`
- `action_type`
- `input_summary`
- `output_summary`
- `sources_used`
- `model_name`
- `created_at`

### `construction_checklists`

- `id`
- `task_id`
- `has_land_document`
- `has_urban_planning_task`
- `has_design_assignment`
- `has_project_estimate`
- `has_expertise_conclusion`
- `has_construction_permit`
- `has_contractor`
- `has_tender_documents`
- `has_technical_supervision`
- `has_author_supervision`
- `has_financing_source`
- `has_acceptance_documents`
- `risk_level`
- `notes`
- `created_at`

## Security talablari

- Maxfiy hujjatlar tashqi AI modelga yuborilmaydi.
- AI savollari, javoblari, manbalari va model nomi audit logga yoziladi.
- Har bir foydalanuvchi faqat o'z tashkiloti ma'lumotlariga kira olishi kerak.
- Frontenddagi permission faqat UI uchun; productionda Firestore Rules yoki Supabase RLS majburiy.
- Prompt injection himoyasi prompt darajasida va server ingestion pipeline darajasida qo'llanadi.
- Audit logni update/delete qilish taqiqlanadi.

## Hozirgi implementatsiya

- UI: `components/panels/legal-ai.html`
- CSS: `css/main.css`
- Logic: `js/app.js`
- Rules example: `firebase/firestore.rules.example`

Joriy static versiya lokal parser va ixtiyoriy Gemini/OpenRouter integratsiyasi bilan ishlaydi. To'liq production RAG uchun backend, vector database, file storage va server-side access control kerak.
