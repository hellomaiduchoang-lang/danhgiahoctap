export function conductVisibility(access) {
  if (access.permissions.has("conduct:view_all")) {
    return "";
  }
  if (access.permissions.has("conduct:view_group") && access.roles.has("ROLE_GROUP_LEADER")) {
    return `AND conduct_records.student_member_id IN (
      SELECT group_members.class_member_id
      FROM group_members
      WHERE group_members.class_id = conduct_records.class_id
        AND group_members.group_id IN (
          SELECT class_groups.id FROM class_groups
          WHERE class_groups.class_id = conduct_records.class_id
            AND class_groups.leader_member_id = $2
        )
    )`;
  }
  if (access.permissions.has("conduct:view_own")) {
    return "AND conduct_records.student_member_id = $2";
  }
  return null;
}
