INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles
CROSS JOIN permissions
WHERE roles.name IN ('ROLE_CLASS_LEADER', 'ROLE_CLASS_DEPUTY')
  AND permissions.name IN ('classes:read', 'students:list', 'conduct:view_all', 'conduct:create')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT roles.id, permissions.id
FROM roles
CROSS JOIN permissions
WHERE roles.name = 'ROLE_GROUP_LEADER'
  AND permissions.name IN ('classes:read', 'conduct:view_group', 'conduct:create')
ON CONFLICT DO NOTHING;
