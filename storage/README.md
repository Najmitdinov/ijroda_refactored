# File Storage

Recommended layout for Firebase Storage or S3-compatible storage:

- `documents/{document_id}/source/{file_name}`
- `documents/{document_id}/ocr/{page}.json`
- `tasks/{task_id}/attachments/{attachment_id}/{file_name}`
- `voice/{telegram_id}/{message_id}.ogg`
- `exports/{document_id}/response-letter.docx`
- `exports/{document_id}/response-letter.pdf`

Rules:

- Signed upload URLs are issued only by backend.
- Frontend never receives AI provider keys or storage admin credentials.
- File metadata is persisted in PostgreSQL `attachments`.
- OCR text is stored as derived data linked to original file.
