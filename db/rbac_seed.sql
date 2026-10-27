-- Banking AI (Customer Service + KYC/AML): roles, permissions and staff users. Loaded by `python -m db.load`.
-- Edit freely: the application reads all of this at request time.

INSERT INTO permissions (permission, description) VALUES
  ('account.read:own',   'View own account and balance'),
  ('account.read:any',   'View any customer''s account and balance'),
  ('txn.read:own',       'View own transactions'),
  ('txn.read:any',       'View any customer''s transactions'),
  ('card.freeze:own',    'Temporarily freeze own card'),
  ('card.freeze:any',    'Temporarily freeze any customer''s card'),
  ('dispute.create:own', 'Dispute a transaction on own account'),
  ('fraud.report:own',   'Report unauthorised use of own card or account'),
  ('kyc.read:own',       'View own KYC status and what documents are needed'),
  ('kyc.read:any',       'View any customer''s KYC status (staff)'),
  ('policy.read',        'Ask questions about bank policy'),
  ('aml.review',         'Run an AML / sanctions review on a customer'),
  ('approval.decide:BLOCK_CARD_PERMANENT', 'Approve or reject a permanent card block'),
  ('approval.decide:FILE_SAR',             'Approve or reject filing a suspicious activity report'),
  ('audit.read',         'Read the audit log'),
  ('rbac.admin',         'Create users and grant or revoke roles');

INSERT INTO roles (role, description) VALUES
  ('customer',           'Retail customer using the assistant'),
  ('support_agent',      'Contact-centre agent helping customers by phone'),
  ('fraud_analyst',      'Card operations: reviews customer-reported misuse, approves permanent card blocks'),
  ('compliance_officer', 'Runs KYC and AML reviews; cannot file SARs'),
  ('mlro',               'Money Laundering Reporting Officer: files SARs'),
  ('auditor',            'Internal audit: read-only access to the audit log'),
  ('rbac_admin',         'Manages users and roles; no business permissions');

INSERT INTO role_permissions (role, permission) VALUES
  ('customer', 'account.read:own'), ('customer', 'txn.read:own'), ('customer', 'card.freeze:own'),
  ('customer', 'dispute.create:own'), ('customer', 'fraud.report:own'), ('customer', 'kyc.read:own'),
  ('customer', 'policy.read'),

  ('support_agent', 'account.read:any'), ('support_agent', 'txn.read:any'), ('support_agent', 'card.freeze:any'),
  ('support_agent', 'kyc.read:any'), ('support_agent', 'policy.read'),

  ('fraud_analyst', 'txn.read:any'), ('fraud_analyst', 'policy.read'),
  ('fraud_analyst', 'approval.decide:BLOCK_CARD_PERMANENT'),

  ('compliance_officer', 'aml.review'), ('compliance_officer', 'kyc.read:any'), ('compliance_officer', 'txn.read:any'),
  ('compliance_officer', 'policy.read'),

  ('mlro', 'aml.review'), ('mlro', 'kyc.read:any'), ('mlro', 'txn.read:any'), ('mlro', 'policy.read'),
  ('mlro', 'approval.decide:FILE_SAR'),

  ('auditor', 'audit.read'),

  ('rbac_admin', 'rbac.admin');

-- Segregation of duties (role_a < role_b alphabetically)
INSERT INTO role_conflicts (role_a, role_b, reason) VALUES
  ('fraud_analyst',      'rbac_admin', 'Admins must not approve business actions'),
  ('compliance_officer', 'rbac_admin', 'Admins must not run investigations'),
  ('mlro',               'rbac_admin', 'Admins must not approve business actions'),
  ('auditor',            'rbac_admin', 'Auditors must be independent of access administration'),
  ('auditor',            'mlro',       'Auditors must be independent of the business they audit'),
  ('auditor',            'compliance_officer', 'Auditors must be independent of the business they audit'),
  ('auditor',            'fraud_analyst',      'Auditors must be independent of the business they audit');

-- Staff users
INSERT INTO users (user_id, display_name) VALUES
  ('support_01',   'Contact-centre agent'),
  ('analyst_01',   'Card operations analyst'),
  ('analyst_02',   'Card operations analyst'),
  ('cmp_02',       'Compliance officer'),
  ('cmp_03',       'Compliance officer'),
  ('mlro_01',      'MLRO'),
  ('mlro_02',      'Deputy MLRO'),
  ('auditor_01',   'Internal auditor'),
  ('admin_01',     'Access administrator');

INSERT INTO user_roles (user_id, role, granted_by) VALUES
  ('support_01', 'support_agent', 'seed'),  ('analyst_01', 'fraud_analyst', 'seed'),
  ('analyst_02', 'fraud_analyst', 'seed'),  ('cmp_02', 'compliance_officer', 'seed'),
  ('cmp_03', 'compliance_officer', 'seed'), ('mlro_01', 'mlro', 'seed'), ('mlro_02', 'mlro', 'seed'),
  ('auditor_01', 'auditor', 'seed'),        ('admin_01', 'rbac_admin', 'seed');

-- Every customer gets a login with the customer role, scoped to their own customer_id
INSERT INTO users (user_id, display_name, customer_id) SELECT customer_id, name, customer_id FROM customers;
INSERT INTO user_roles (user_id, role, granted_by) SELECT customer_id, 'customer', 'seed' FROM customers;
