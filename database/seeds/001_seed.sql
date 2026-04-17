INSERT INTO users (username, email, role, password_hash)
VALUES (
    'solo_researcher',
    'solo@example.com',
    'admin',
    '$2a$10$Vdbrb5tUsmaB8e2uPUQ05Otprw11OK04IuOBT2jP010uWODjR/tF2'
)
ON CONFLICT (username) DO NOTHING;

INSERT INTO users (username, email, role, password_hash)
VALUES (
    'admin_root',
    'admin@securebounty.local',
    'admin',
    '$2a$10$Vdbrb5tUsmaB8e2uPUQ05Otprw11OK04IuOBT2jP010uWODjR/tF2'
)
ON CONFLICT (username) DO NOTHING;

INSERT INTO projects (name, scope, owner_user_id)
SELECT 'Portfolio Program', '*.example.com', id
FROM users
WHERE username = 'solo_researcher'
ON CONFLICT DO NOTHING;

INSERT INTO findings (project_id, title, severity, cvss_score, description, status)
SELECT p.id,
       'Reflected XSS on search endpoint',
       'high',
       7.2,
       'Payload can execute script in victim browser through unsanitized query parameter.',
       'open'
FROM projects p
WHERE p.name = 'Portfolio Program'
LIMIT 1;
