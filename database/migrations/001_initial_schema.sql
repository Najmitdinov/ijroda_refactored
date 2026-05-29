create extension if not exists "uuid-ossp";

do $$ begin
  create type user_role as enum ('SUPER_ADMIN','RAHBAR','NAZORATCHI','IJROCHI','KUZATUVCHI');
exception when duplicate_object then null;
end $$;

do $$ begin
  create type task_priority as enum ('LOW','NORMAL','IMPORTANT','URGENT','CRITICAL');
exception when duplicate_object then null;
end $$;

do $$ begin
  create type task_status as enum ('NEW','IN_PROGRESS','DONE','OVERDUE','CANCELLED');
exception when duplicate_object then null;
end $$;

do $$ begin
  create type notification_channel as enum ('TELEGRAM','EMAIL','PUSH');
exception when duplicate_object then null;
end $$;

create table if not exists departments (
  department_id uuid primary key default uuid_generate_v4(),
  name text not null unique,
  parent_department_id uuid references departments(department_id),
  created_at timestamptz not null default now()
);

create table if not exists employees (
  employee_id uuid primary key default uuid_generate_v4(),
  ism text not null,
  familiya text not null,
  sharif text default '',
  bolim text not null,
  lavozim text not null,
  telefon text default '',
  telegram_id text unique,
  username text,
  aliases text[] not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists users (
  user_id uuid primary key default uuid_generate_v4(),
  employee_id uuid references employees(employee_id),
  email text not null unique,
  password_hash text not null,
  role user_role not null default 'IJROCHI',
  two_factor_enabled boolean not null default false,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists login_logs (
  login_log_id uuid primary key default uuid_generate_v4(),
  user_id uuid references users(user_id),
  ip_address inet,
  user_agent text,
  created_at timestamptz not null default now()
);

create table if not exists documents (
  document_id uuid primary key default uuid_generate_v4(),
  document_title text not null,
  source_file_name text,
  mime_type text,
  extracted_text text,
  ai_summary text,
  priority task_priority not null default 'NORMAL',
  status text not null default 'NEW',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists tasks (
  task_id uuid primary key default uuid_generate_v4(),
  document_id uuid references documents(document_id) on delete cascade,
  executor_employee_id uuid references employees(employee_id),
  department_id uuid references departments(department_id),
  title text not null,
  summary text not null,
  deadline timestamptz,
  priority task_priority not null default 'NORMAL',
  status task_status not null default 'NEW',
  ai_confidence numeric(5,2),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists task_history (
  history_id uuid primary key default uuid_generate_v4(),
  task_id uuid references tasks(task_id) on delete cascade,
  actor_user_id uuid references users(user_id),
  old_status task_status,
  new_status task_status,
  comment text,
  created_at timestamptz not null default now()
);

create table if not exists attachments (
  attachment_id uuid primary key default uuid_generate_v4(),
  task_id uuid references tasks(task_id) on delete cascade,
  document_id uuid references documents(document_id) on delete cascade,
  uploaded_by_user_id uuid references users(user_id),
  uploaded_by_telegram_id text,
  file_kind text not null,
  storage_path text,
  metadata jsonb not null default '{}',
  created_at timestamptz not null default now()
);

create table if not exists comments (
  comment_id uuid primary key default uuid_generate_v4(),
  task_id uuid references tasks(task_id) on delete cascade,
  author_user_id uuid references users(user_id),
  body text not null,
  created_at timestamptz not null default now()
);

create table if not exists notifications (
  notification_id uuid primary key default uuid_generate_v4(),
  user_id uuid references users(user_id),
  employee_id uuid references employees(employee_id),
  channel notification_channel not null,
  title text not null,
  body text not null,
  priority task_priority not null default 'NORMAL',
  metadata jsonb not null default '{}',
  sent_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists logs (
  log_id uuid primary key default uuid_generate_v4(),
  actor_user_id uuid references users(user_id),
  action text not null,
  entity_type text not null,
  entity_id uuid,
  ip_address inet,
  user_agent text,
  metadata jsonb not null default '{}',
  created_at timestamptz not null default now()
);

create table if not exists analytics (
  analytics_id uuid primary key default uuid_generate_v4(),
  metric_key text not null,
  metric_value numeric not null,
  dimensions jsonb not null default '{}',
  measured_at timestamptz not null default now()
);

create table if not exists telegram_sessions (
  telegram_id text primary key,
  employee_id uuid references employees(employee_id),
  username text,
  first_name text,
  last_name text,
  state text not null default 'ACTIVE',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_tasks_executor_status on tasks(executor_employee_id, status);
create index if not exists idx_tasks_deadline on tasks(deadline);
create index if not exists idx_tasks_priority on tasks(priority);
create index if not exists idx_documents_priority on documents(priority);
create index if not exists idx_logs_actor_created on logs(actor_user_id, created_at desc);
create index if not exists idx_notifications_employee_sent on notifications(employee_id, sent_at);
