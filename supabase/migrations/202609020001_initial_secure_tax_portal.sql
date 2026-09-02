-- TSC Elite Tax Portal: account isolation and least-privilege access
create extension if not exists pgcrypto;
create type public.app_role as enum ('owner_admin','tax_preparer','tax_client','support_staff');
create type public.account_status as enum ('pending','active','suspended');
create type public.case_status as enum ('intake_started','documents_pending','preparer_review','client_review','ready_to_file','filed','completed','on_hold');

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '', phone text, role public.app_role not null default 'tax_client',
  status public.account_status not null default 'pending', created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table public.preparer_applications (
  id uuid primary key default gen_random_uuid(), full_name text not null, email text not null, phone text not null,
  business_name text, ptin_status text not null, efin_status text not null, experience_years integer, estimated_clients integer,
  goals text not null, consent text, status text not null default 'submitted', assigned_to uuid references public.profiles(id), created_at timestamptz not null default now()
);
create table public.tax_cases (
  id uuid primary key default gen_random_uuid(), client_id uuid not null references public.profiles(id), preparer_id uuid references public.profiles(id),
  tax_year integer not null, status public.case_status not null default 'intake_started', filing_type text, internal_notes text,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(), unique(client_id,tax_year)
);
create table public.documents (
  id uuid primary key default gen_random_uuid(), case_id uuid not null references public.tax_cases(id) on delete cascade,
  uploaded_by uuid not null references public.profiles(id), file_name text not null, storage_path text not null unique,
  document_type text, review_status text not null default 'received', created_at timestamptz not null default now()
);
create table public.appointments (
  id uuid primary key default gen_random_uuid(), client_id uuid not null references public.profiles(id), preparer_id uuid references public.profiles(id),
  starts_at timestamptz not null, appointment_type text not null, status text not null default 'scheduled', notes text, created_at timestamptz not null default now()
);
create table public.support_tickets (
  id uuid primary key default gen_random_uuid(), opened_by uuid not null references public.profiles(id), assigned_to uuid references public.profiles(id),
  subject text not null, description text not null, priority text not null default 'normal', status text not null default 'open', created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table public.portal_messages (
  id uuid primary key default gen_random_uuid(), sender_id uuid not null references public.profiles(id), recipient_id uuid not null references public.profiles(id),
  case_id uuid references public.tax_cases(id) on delete cascade, body text not null, read_at timestamptz, created_at timestamptz not null default now()
);

create or replace function public.current_role() returns public.app_role language sql stable security definer set search_path=public as $$select role from profiles where id=auth.uid()$$;
create or replace function public.is_staff() returns boolean language sql stable security definer set search_path=public as $$select coalesce(current_role() in ('owner_admin','support_staff'),false)$$;
create or replace function public.can_access_case(case_uuid uuid) returns boolean language sql stable security definer set search_path=public as $$select exists(select 1 from tax_cases c where c.id=case_uuid and (c.client_id=auth.uid() or c.preparer_id=auth.uid() or is_staff()))$$;
grant execute on function public.current_role() to authenticated;
grant execute on function public.is_staff() to authenticated;
grant execute on function public.can_access_case(uuid) to authenticated;

create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
begin insert into profiles(id,full_name,phone,role,status) values(new.id,coalesce(new.raw_user_meta_data->>'full_name',''),new.raw_user_meta_data->>'phone','tax_client','pending'); return new; end;$$;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.preparer_applications enable row level security;
alter table public.tax_cases enable row level security;
alter table public.documents enable row level security;
alter table public.appointments enable row level security;
alter table public.support_tickets enable row level security;
alter table public.portal_messages enable row level security;

create policy "profile own or staff read" on public.profiles for select to authenticated using(id=auth.uid() or is_staff() or (current_role()='tax_preparer' and role='tax_client' and exists(select 1 from tax_cases c where c.client_id=profiles.id and c.preparer_id=auth.uid())));
create policy "admin manages profiles" on public.profiles for all to authenticated using(current_role()='owner_admin') with check(current_role()='owner_admin');
create policy "public submits preparer application" on public.preparer_applications for insert to anon,authenticated with check(status='submitted' and assigned_to is null);
create policy "staff manages applications" on public.preparer_applications for all to authenticated using(is_staff()) with check(is_staff());
create policy "case parties or staff read" on public.tax_cases for select to authenticated using(client_id=auth.uid() or preparer_id=auth.uid() or is_staff());
create policy "client creates own case" on public.tax_cases for insert to authenticated with check(client_id=auth.uid() and preparer_id is null and status='intake_started');
create policy "preparer and staff manage cases" on public.tax_cases for all to authenticated using(preparer_id=auth.uid() or is_staff()) with check(preparer_id=auth.uid() or is_staff());
create policy "case parties read documents" on public.documents for select to authenticated using(can_access_case(case_id));
create policy "case parties upload documents" on public.documents for insert to authenticated with check(uploaded_by=auth.uid() and can_access_case(case_id));
create policy "staff and assigned preparer manage documents" on public.documents for update to authenticated using(is_staff() or exists(select 1 from tax_cases c where c.id=case_id and c.preparer_id=auth.uid()));
create policy "appointment parties or staff read" on public.appointments for select to authenticated using(client_id=auth.uid() or preparer_id=auth.uid() or is_staff());
create policy "client schedules own appointment" on public.appointments for insert to authenticated with check(client_id=auth.uid());
create policy "preparer and staff manage appointments" on public.appointments for all to authenticated using(preparer_id=auth.uid() or is_staff()) with check(preparer_id=auth.uid() or is_staff());
create policy "ticket owner or staff read" on public.support_tickets for select to authenticated using(opened_by=auth.uid() or is_staff());
create policy "users open own tickets" on public.support_tickets for insert to authenticated with check(opened_by=auth.uid() and assigned_to is null);
create policy "staff manages tickets" on public.support_tickets for all to authenticated using(is_staff()) with check(is_staff());
create policy "message participants or staff read" on public.portal_messages for select to authenticated using(sender_id=auth.uid() or recipient_id=auth.uid() or is_staff());
create policy "users send as themselves" on public.portal_messages for insert to authenticated with check(sender_id=auth.uid() and (is_staff() or recipient_id=auth.uid() or exists(select 1 from tax_cases c where (c.client_id=sender_id and c.preparer_id=recipient_id) or (c.preparer_id=sender_id and c.client_id=recipient_id))));

-- Users edit contact fields only through this RPC. Role and status are never client-editable.
create or replace function public.update_my_profile(new_full_name text,new_phone text) returns void language plpgsql security definer set search_path=public as $$
begin update profiles set full_name=trim(new_full_name),phone=trim(new_phone),updated_at=now() where id=auth.uid(); end;$$;
grant execute on function public.update_my_profile(text,text) to authenticated;

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types) values('tax-documents','tax-documents',false,15728640,array['application/pdf','image/jpeg','image/png','image/heic']) on conflict(id) do nothing;
create policy "authorized users read tax files" on storage.objects for select to authenticated using(bucket_id='tax-documents' and can_access_case(((storage.foldername(name))[1])::uuid));
create policy "authorized users upload tax files" on storage.objects for insert to authenticated with check(bucket_id='tax-documents' and can_access_case(((storage.foldername(name))[1])::uuid));
create policy "staff or uploader removes tax files" on storage.objects for delete to authenticated using(bucket_id='tax-documents' and (owner_id=auth.uid()::text or is_staff()));

-- Only a database administrator may bootstrap the first owner. Replace the email before running manually:
-- update profiles set role='owner_admin',status='active' where id=(select id from auth.users where email='OWNER_EMAIL');
