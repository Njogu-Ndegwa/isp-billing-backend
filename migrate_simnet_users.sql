-- ============================================
-- PPPoE Customer Migration for SIMNET (user_id=44)
-- ============================================
-- Step 1: Run this first to see available plans & routers:
--   docker exec -i isp_billing_postgres psql -U isp_user -d isp_billing_db < migrate_simnet_users.sql
--
-- Step 2: After checking output, update PLAN_ID and ROUTER_ID below, then run again.
-- ============================================

-- Show available plans and routers for SIMNET (user_id=44)
\echo '=== Plans for SIMNET (user_id=44) ==='
SELECT id, name, speed, price, connection_type FROM plans WHERE user_id = 44 ORDER BY id;

\echo '=== Routers for SIMNET (user_id=44) ==='
SELECT id, name, ip_address FROM routers WHERE user_id = 44 ORDER BY id;

-- ============================================
-- SET THESE BEFORE RUNNING THE INSERTS
-- ============================================
\set PLAN_ID NULL
\set ROUTER_ID NULL

-- Insert customers (skips if pppoe_username already exists for this user)
INSERT INTO customers (name, phone, pppoe_username, pppoe_password, status, plan_id, user_id, router_id, created_at)
SELECT v.name, v.phone, v.pppoe_username, v.pppoe_password, 'inactive', :PLAN_ID, 44, :ROUTER_ID, NOW()
FROM (VALUES
  ('Damaris M',     '0721783010',    'Molly',     'Molly'),
  ('Salomon Ki',    '0729450175',    'Suleiman',  'Suleiman'),
  ('Eve Chumo',     '0726834799',    'Jan12',     'Jan12'),
  ('Susan Cher',    '0728862573',    'Utalii',    'Utalii12'),
  ('ABRAHAM',       '0722937839',    'Kemboi',    'Kemboi'),
  ('JOB TUWEI',     '0715455045',    'Tuwei123',  'Tuwei123'),
  ('Mike Maley',    '254720135094',  'Maleya',    'Maleya'),
  ('Hilda Aruse',   '254720475687',  'Hilda12',   'Hilda12'),
  ('Patroba Tio',   '0723936724',    'Sam',       'Sam'),
  ('DONALD AE',     '0723674000',    'Donald',    'Donald'),
  ('Lazurus Rof',   '254723076384',  'Rotich12',  'Rotich12'),
  ('Rose Tuwei',    '0729988870',    'Rose123',   'Rose123'),
  ('Lucy Wanga',    '254704826223',  'Wangari',   'Wangari'),
  ('Mike Tanui',    '254720313699',  'Tanui12',   'Tanui12'),
  ('Velton Kim',    '0740625527',    'Velton',    'Velton'),
  ('Ruth Soimo',    '61414377508',   'Chepkulei', 'Chepkulei'),
  ('Samwel TA',     '0721747732',    'Greatvale', 'Greatvale'),
  ('KEVIN LAGA',    '254727233740',  'Kevin12',   'Kevin12'),
  ('Enock Bett',    '0721285833',    'Enock',     'Enock'),
  ('Nancy',         '0705707577',    'Maiyo12',   'Maiyo12'),
  ('Collins Kose',  '0703699299',    'Kosgei',    'Kosgei'),
  ('Tuiyobei Pr',   '0723076384',    'Tuiyobei',  'Tuiyobei'),
  ('Eliud Tuwei',   '0720951788',    'Eliud12',   'Eliud12')
) AS v(name, phone, pppoe_username, pppoe_password)
WHERE NOT EXISTS (
  SELECT 1 FROM customers c
  WHERE c.pppoe_username = v.pppoe_username AND c.user_id = 44
);

\echo '=== Inserted customers ==='
SELECT id, name, phone, pppoe_username, pppoe_password, status
FROM customers WHERE user_id = 44 ORDER BY id DESC LIMIT 25;
