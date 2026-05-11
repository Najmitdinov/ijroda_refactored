# Ijro Hisoboti Professional System Architecture

Bu hujjat joriy static/Firebase dashboardni production-level mini ERP / monitoring system darajasiga olib chiqish uchun target architecture hisoblanadi.

## 1. Product Target

Ijro Hisoboti oddiy CRUD dashboard emas. Yakuniy mahsulot quyidagi yo'nalishlarni qamrab oladi:

- monitoring
- task management
- deadlines
- analytics
- reporting
- AI insights
- notifications
- audit tracking
- organization and employee performance

## 2. Recommended Stack

### Frontend

- Next.js 15
- TypeScript
- TailwindCSS
- shadcn/ui
- Framer Motion
- Zustand
- TanStack Table
- ApexCharts yoki ECharts

### Backend

Eng tavsiya qilinadigan variant:

- Supabase
- PostgreSQL
- Supabase Auth
- Supabase Storage
- Row Level Security

Enterprise variant:

- NestJS
- PostgreSQL
- Prisma
- Redis
- S3-compatible storage

### Deploy

- Frontend: Vercel
- Database/Auth/Storage: Supabase
- Static legacy version: GitHub Pages

## 3. Application Modules

```text
/app
  /dashboard
  /tasks
  /reports
  /analytics
  /notifications
  /users
  /organizations
  /deadlines
  /documents
  /ai-insights
  /settings
```

## 4. Sidebar Structure

```text
Dashboard

Topshiriqlar
  Active
  Completed
  Overdue
  Drafts

Hisobotlar
  Daily
  Weekly
  Monthly
  Custom

Analitika
  Performance
  Trends
  Organizations
  Employees

Notifications
Tashkilotlar
Users
Hujjatlar
AI Insights
Settings
```

## 5. Dashboard Page

### KPI Cards

- All Tasks
- Completed
- Pending
- Overdue
- Efficiency %

### Charts

- Weekly Performance
- Organization Statistics
- Task Completion Trend
- Deadline Risk Trend

### Tables

- Latest Tasks
- Deadline Alerts
- Recent Activities
- Overdue Tasks

## 6. Database Schema

### users

```sql
create table users (
  id uuid primary key default gen_random_uuid(),
  fullname text not null,
  email text unique not null,
  role text not null default 'user',
  organization_id uuid references organizations(id),
  avatar text,
  created_at timestamptz not null default now()
);
```

### organizations

```sql
create table organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  region text,
  type text,
  created_at timestamptz not null default now()
);
```

### tasks

```sql
create table tasks (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text,
  status text not null default 'active',
  priority text not null default 'normal',
  deadline timestamptz,
  assigned_to uuid references users(id),
  created_by uuid references users(id),
  organization_id uuid references organizations(id),
  progress int not null default 0,
  attachment text,
  created_at timestamptz not null default now()
);
```

### reports

```sql
create table reports (
  id uuid primary key default gen_random_uuid(),
  task_id uuid references tasks(id) on delete cascade,
  report_text text,
  report_file text,
  submitted_by uuid references users(id),
  created_at timestamptz not null default now()
);
```

### notifications

```sql
create table notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references users(id) on delete cascade,
  title text not null,
  body text,
  read_status boolean not null default false,
  created_at timestamptz not null default now()
);
```

### audit_logs

```sql
create table audit_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references users(id),
  action text not null,
  target text,
  old_value jsonb,
  new_value jsonb,
  created_at timestamptz not null default now()
);
```

### ai_insights

```sql
create table ai_insights (
  id uuid primary key default gen_random_uuid(),
  task_id uuid references tasks(id) on delete cascade,
  prediction text,
  risk_level text,
  generated_at timestamptz not null default now()
);
```

## 7. Frontend Structure

```text
/src
  /app
  /components
    /dashboard
    /charts
    /tables
    /cards
    /layout
    /forms
    /modals
  /hooks
  /services
  /store
  /types
  /utils
  /lib
```

## 8. Services Layer

```text
/services
  authService.ts
  taskService.ts
  reportService.ts
  organizationService.ts
  notificationService.ts
  aiInsightService.ts
  auditService.ts
```

## 9. UI Components

- Collapsible Sidebar
- Sticky Navbar
- Command Menu
- Global Search
- KPI Cards
- Activity Timeline
- Charts
- Heatmaps
- Progress Rings
- Data Table
- Server Pagination
- Multi Filter
- Column Sorting
- Export Button
- Calendar View
- Kanban Board
- Task Timeline
- Drag and Drop
- Rich Text Editor
- Skeleton Loaders
- Toast Notifications
- Empty States
- Confirmation Dialogs

## 10. Roadmap

### Phase 1: Core System

- Authentication
- Roles
- Tasks CRUD
- Assignments
- Reports
- File upload
- PDF/Excel export
- Dashboard statistics

### Phase 2: Professional System

- Real-time notifications
- Telegram bot alerts
- Trend analysis
- Organization rating
- Deadline countdown
- Overdue alerts
- Activity logs

### Phase 3: Enterprise Level

- AI summaries
- Risk prediction
- Auto reports
- OCR document scanning
- Voice input
- Advanced permissions
- Multi-role hierarchy

### Phase 4: Premium Version

- Flutter mobile app
- Android and iOS
- Offline mode
- Real-time collaboration
- Advanced AI assistant

## 11. Migration Strategy

Joriy GitHub Pages versiya ishlashda davom etadi. Production versiya alohida branch yoki yangi repo sifatida yaratiladi:

```text
legacy-static  -> current GitHub Pages version
main           -> stable public version
next-supabase  -> production migration branch
```

Tavsiya:

1. Joriy static appni buzmaslik.
2. `next-supabase` branchda Next.js scaffold yaratish.
3. Supabase schema va authni alohida ulash.
4. Avval Dashboard, Tasks, Organizations modullarini ko'chirish.
5. Excel import va AI hisobotlarni keyingi bosqichda service layerga ajratish.

