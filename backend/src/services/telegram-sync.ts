import { query } from '../db/pool.js';
import { enqueueNotification } from './notification-engine.js';

export type TelegramSyncOrganization = {
  externalId?: string;
  name: string;
  address?: string;
};

export type TelegramSyncEmployee = {
  externalId?: string;
  organizationExternalId?: string;
  organizationName?: string;
  fullName: string;
  phone?: string;
  position?: string;
  department?: string;
  active?: boolean;
};

export type TelegramSyncLetter = {
  externalId: string;
  organizationExternalId?: string;
  organizationName?: string;
  employeeExternalId?: string;
  executorName?: string;
  letterNumber?: string;
  subject: string;
  body?: string;
  deadline?: string;
  status?: string;
  urgency?: 'LOW' | 'NORMAL' | 'IMPORTANT' | 'URGENT' | 'CRITICAL';
  sourceOrganization?: string;
};

function splitFullName(fullName: string) {
  const parts = String(fullName || '').replace(/\s+/g, ' ').trim().split(' ').filter(Boolean);
  return {
    familiya: parts[0] || 'Noma’lum',
    ism: parts[1] || parts[0] || 'Xodim',
    sharif: parts.slice(2).join(' ')
  };
}

async function upsertOrganization(input: TelegramSyncOrganization) {
  const name = input.name.trim();
  const externalId = input.externalId?.trim() || '';
  const existing = await query<{ organization_id: string }>(
    `select organization_id
     from organizations
     where ($1 <> '' and external_id = $1)
        or lower(name) = lower($2)
     order by case when external_id = $1 then 0 else 1 end
     limit 1`,
    [externalId, name]
  );
  if (existing.rows[0]) {
    const updated = await query<{ organization_id: string }>(
      `update organizations set
         name = $2,
         address = case when $3 <> '' then $3 else address end,
         external_id = coalesce(nullif($4, ''), external_id),
         updated_at = now()
       where organization_id = $1
       returning organization_id`,
      [existing.rows[0].organization_id, name, input.address?.trim() || '', externalId]
    );
    return updated.rows[0]?.organization_id || null;
  }
  const result = await query<{ organization_id: string }>(
    `insert into organizations (name, address, external_id)
     values ($1, $2, nullif($3, ''))
     returning organization_id`,
    [name, input.address?.trim() || '', externalId]
  );
  return result.rows[0]?.organization_id || null;
}

async function findOrganizationId(externalId = '', name = '') {
  if (externalId) {
    const found = await query<{ organization_id: string }>(
      'select organization_id from organizations where external_id = $1 limit 1',
      [externalId]
    );
    if (found.rows[0]) return found.rows[0].organization_id;
  }
  if (name) return upsertOrganization({ externalId, name });
  return null;
}

async function upsertEmployee(input: TelegramSyncEmployee) {
  const organizationId = await findOrganizationId(input.organizationExternalId, input.organizationName);
  const names = splitFullName(input.fullName);
  const externalId = input.externalId?.trim() || '';
  const existing = externalId
    ? await query<{ employee_id: string }>('select employee_id from employees where external_id = $1 limit 1', [externalId])
    : await query<{ employee_id: string }>(
        `select employee_id from employees
         where lower(concat_ws(' ', familiya, ism, sharif)) = lower($1)
         limit 1`,
        [input.fullName.trim()]
      );

  if (existing.rows[0]) {
    const updated = await query<{ employee_id: string }>(
      `update employees set
         organization_id = coalesce($2, organization_id),
         ism = $3,
         familiya = $4,
         sharif = $5,
         telefon = case when $6 <> '' then $6 else telefon end,
         lavozim = case when $7 <> '' then $7 else lavozim end,
         bolim = case when $8 <> '' then $8 else bolim end,
         active = $9,
         external_id = coalesce(nullif($10, ''), external_id),
         updated_at = now()
       where employee_id = $1
       returning employee_id`,
      [
        existing.rows[0].employee_id,
        organizationId,
        names.ism,
        names.familiya,
        names.sharif,
        input.phone?.trim() || '',
        input.position?.trim() || '',
        input.department?.trim() || '',
        input.active !== false,
        externalId
      ]
    );
    return updated.rows[0]?.employee_id || null;
  }

  const inserted = await query<{ employee_id: string }>(
    `insert into employees
       (organization_id, ism, familiya, sharif, telefon, lavozim, bolim, active, external_id)
     values ($1,$2,$3,$4,$5,$6,$7,$8,nullif($9,''))
     returning employee_id`,
    [
      organizationId,
      names.ism,
      names.familiya,
      names.sharif,
      input.phone?.trim() || '',
      input.position?.trim() || 'Ijrochi',
      input.department?.trim() || 'Bosh boshqarma',
      input.active !== false,
      externalId
    ]
  );
  return inserted.rows[0]?.employee_id || null;
}

async function findEmployeeId(externalId = '', fullName = '') {
  if (externalId) {
    const found = await query<{ employee_id: string }>(
      'select employee_id from employees where external_id = $1 limit 1',
      [externalId]
    );
    if (found.rows[0]) return found.rows[0].employee_id;
  }
  if (fullName) {
    const found = await query<{ employee_id: string }>(
      `select employee_id from employees
       where lower(concat_ws(' ', familiya, ism, sharif)) = lower($1)
          or lower(concat_ws(' ', ism, familiya, sharif)) = lower($1)
          or (
            lower(familiya) = lower(split_part($1, ' ', 1))
            and lower(ism) like lower(split_part($1, ' ', 2)) || '%'
          )
          or exists (
            select 1 from unnest(aliases) alias
            where lower(alias) = lower($1)
          )
       limit 1`,
      [fullName.trim()]
    );
    if (found.rows[0]) return found.rows[0].employee_id;
  }
  return null;
}

async function upsertLetter(input: TelegramSyncLetter) {
  const organizationId = await findOrganizationId(input.organizationExternalId, input.organizationName);
  const employeeId = await findEmployeeId(input.employeeExternalId, input.executorName);
  const previous = await query<{ employee_id: string | null; status: string }>(
    'select employee_id, status from letters where external_id = $1',
    [input.externalId]
  );
  const result = await query<{ letter_id: string; employee_id: string | null }>(
    `insert into letters
       (external_id, organization_id, employee_id, letter_number, subject, body, deadline, status, urgency, source_organization)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     on conflict (external_id) do update set
       organization_id = coalesce(excluded.organization_id, letters.organization_id),
       employee_id = coalesce(excluded.employee_id, letters.employee_id),
       letter_number = excluded.letter_number,
       subject = excluded.subject,
       body = excluded.body,
       deadline = excluded.deadline,
       status = case
         when letters.status in ('DONE', 'CANCELLED')
           and excluded.status not in ('DONE', 'CANCELLED')
         then letters.status
         else excluded.status
       end,
       urgency = excluded.urgency,
       source_organization = excluded.source_organization,
       updated_at = now()
     returning letter_id, employee_id`,
    [
      input.externalId,
      organizationId,
      employeeId,
      input.letterNumber?.trim() || '',
      input.subject.trim(),
      input.body?.trim() || '',
      input.deadline || null,
      input.status?.trim() || 'NEW',
      input.urgency || 'NORMAL',
      input.sourceOrganization?.trim() || ''
    ]
  );
  const letter = result.rows[0];
  const assignmentChanged = Boolean(
    letter?.employee_id
    && (!previous.rows[0] || previous.rows[0].employee_id !== letter.employee_id)
  );
  if (letter?.employee_id && assignmentChanged) {
    await enqueueNotification({
      employeeId: letter.employee_id,
      channel: 'TELEGRAM',
      title: 'Yangi xat biriktirildi',
      body: input.body?.trim() || input.subject.trim(),
      priority: input.urgency || 'NORMAL',
      metadata: {
        letter_id: letter.letter_id,
        external_id: input.externalId,
        letter_number: input.letterNumber || ''
      }
    });
  }
  return { letterId: letter?.letter_id || null, employeeId, assignmentChanged };
}

export async function syncTelegramBotData(input: {
  organizations?: TelegramSyncOrganization[];
  employees?: TelegramSyncEmployee[];
  letters?: TelegramSyncLetter[];
}) {
  let organizationCount = 0;
  let employeeCount = 0;
  let letterCount = 0;
  let queuedNotifications = 0;

  for (const organization of input.organizations || []) {
    if (!organization.name?.trim()) continue;
    if (await upsertOrganization(organization)) organizationCount += 1;
  }
  for (const employee of input.employees || []) {
    if (!employee.fullName?.trim()) continue;
    if (await upsertEmployee(employee)) employeeCount += 1;
  }
  for (const letter of input.letters || []) {
    if (!letter.externalId?.trim() || !letter.subject?.trim()) continue;
    const saved = await upsertLetter(letter);
    if (saved.letterId) letterCount += 1;
    if (saved.assignmentChanged) queuedNotifications += 1;
  }

  return {
    organizations: organizationCount,
    employees: employeeCount,
    letters: letterCount,
    queuedNotifications
  };
}
