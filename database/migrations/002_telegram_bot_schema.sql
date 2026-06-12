create table if not exists organizations (
  organization_id uuid primary key default uuid_generate_v4(),
  name text not null unique,
  address text default '',
  external_id text unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table employees add column if not exists organization_id uuid references organizations(organization_id);
alter table employees add column if not exists bot_status text not null default 'NOT_LINKED';
alter table employees add column if not exists registered_at timestamptz;
alter table employees add column if not exists active boolean not null default true;
alter table employees add column if not exists external_id text;
create unique index if not exists idx_employees_external_id on employees(external_id) where external_id is not null;

create table if not exists letters (
  letter_id uuid primary key default uuid_generate_v4(),
  organization_id uuid references organizations(organization_id),
  employee_id uuid references employees(employee_id),
  document_id uuid references documents(document_id) on delete set null,
  task_id uuid references tasks(task_id) on delete set null,
  external_id text unique,
  letter_number text default '',
  subject text not null,
  body text default '',
  deadline date,
  status text not null default 'NEW',
  urgency task_priority not null default 'NORMAL',
  source_organization text default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists notification_logs (
  notification_log_id uuid primary key default uuid_generate_v4(),
  employee_id uuid references employees(employee_id) on delete set null,
  letter_id uuid references letters(letter_id) on delete set null,
  notification_id uuid references notifications(notification_id) on delete set null,
  sent_at timestamptz not null default now(),
  notification_type text not null,
  successful boolean not null default false,
  telegram_message_id text,
  error_message text default '',
  metadata jsonb not null default '{}'
);

create table if not exists bot_settings (
  employee_id uuid primary key references employees(employee_id) on delete cascade,
  reminder_time time not null default '09:00',
  active boolean not null default true,
  language text not null default 'uz',
  timezone text not null default 'Asia/Tashkent',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint bot_settings_language_check check (language in ('uz', 'uz_cyrl', 'ru'))
);

alter table notifications add column if not exists letter_id uuid references letters(letter_id) on delete set null;

create index if not exists idx_employees_organization on employees(organization_id);
create index if not exists idx_employees_bot_status on employees(bot_status, active);
create index if not exists idx_letters_employee_status on letters(employee_id, status);
create index if not exists idx_letters_deadline on letters(deadline);
create index if not exists idx_letters_organization on letters(organization_id);
create index if not exists idx_notification_logs_employee_sent on notification_logs(employee_id, sent_at desc);
create index if not exists idx_notification_logs_letter on notification_logs(letter_id);
