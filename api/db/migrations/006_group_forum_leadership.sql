ALTER TABLE class_groups
  ADD COLUMN leader_member_id UUID;

ALTER TABLE class_groups
  ADD CONSTRAINT class_groups_leader_member_fk
  FOREIGN KEY (class_id, leader_member_id) REFERENCES class_members(class_id, id);

UPDATE class_groups
SET leader_member_id = (
  SELECT group_members.class_member_id
  FROM group_members
  JOIN class_member_roles ON class_member_roles.class_member_id = group_members.class_member_id
  JOIN roles ON roles.id = class_member_roles.role_id
  WHERE group_members.group_id = class_groups.id
    AND group_members.class_id = class_groups.class_id
    AND roles.name = 'ROLE_GROUP_LEADER'
  ORDER BY class_member_roles.granted_at DESC
  LIMIT 1
);

ALTER TABLE class_forum_posts
  ADD COLUMN group_id UUID;

ALTER TABLE class_forum_posts
  ADD CONSTRAINT class_forum_posts_group_fk
  FOREIGN KEY (group_id, class_id) REFERENCES class_groups(id, class_id) ON DELETE CASCADE;

ALTER TABLE class_forum_posts
  DROP CONSTRAINT IF EXISTS class_forum_posts_class_id_week_start_key;

CREATE UNIQUE INDEX class_forum_posts_group_week_unique_idx
  ON class_forum_posts (class_id, group_id, week_start)
  WHERE group_id IS NOT NULL;

CREATE INDEX class_groups_leader_idx ON class_groups (class_id, leader_member_id);
