import test from "node:test";
import assert from "node:assert/strict";
import { conductVisibility } from "../src/authorization.js";

const access = (roles, permissions) => ({
  roles: new Set(roles),
  permissions: new Set(permissions)
});

test("teachers with conduct:view_all receive the full class scope", () => {
  assert.equal(
    conductVisibility(access(["ROLE_TEACHER"], ["conduct:view_all"])),
    ""
  );
});

test("students with conduct:view_own are restricted to their membership", () => {
  assert.equal(
    conductVisibility(access(["ROLE_STUDENT"], ["conduct:view_own"])),
    "AND conduct_records.student_member_id = $2"
  );
});

test("group leaders are restricted to their assigned groups", () => {
  const scope = conductVisibility(access(
    ["ROLE_STUDENT", "ROLE_GROUP_LEADER"],
    ["conduct:view_own", "conduct:view_group"]
  ));
  assert.match(scope, /group_members\.class_member_id/);
  assert.match(scope, /class_groups\.leader_member_id = \$2/);
  assert.match(scope, /group_members\.group_id IN/);
  assert.doesNotMatch(scope, /conduct_records\.student_member_id = \$2$/);
});

test("class leaders without conduct permission cannot access conduct records", () => {
  assert.equal(
    conductVisibility(access(["ROLE_CLASS_LEADER"], ["classes:read", "students:list"])),
    null
  );
});
