CREATE TABLE class_weekly_point_periods (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  academic_year TEXT NOT NULL DEFAULT '',
  week_start DATE NOT NULL,
  week_end DATE NOT NULL,
  period_started_at TIMESTAMPTZ NOT NULL,
  reset_by_member_id UUID NOT NULL,
  archived_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (week_end >= week_start),
  FOREIGN KEY (class_id, reset_by_member_id) REFERENCES class_members(class_id, id)
);

CREATE TABLE class_weekly_point_scores (
  period_id UUID NOT NULL REFERENCES class_weekly_point_periods(id) ON DELETE CASCADE,
  class_id UUID NOT NULL,
  class_member_id UUID NOT NULL,
  student_number TEXT NOT NULL,
  full_name TEXT NOT NULL,
  positive_points INTEGER NOT NULL DEFAULT 0,
  negative_points INTEGER NOT NULL DEFAULT 0,
  total_points INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (period_id, class_member_id),
  FOREIGN KEY (class_id, class_member_id) REFERENCES class_members(class_id, id),
  CHECK (positive_points >= 0 AND negative_points >= 0),
  CHECK (total_points = positive_points - negative_points)
);

CREATE INDEX class_weekly_point_scores_member_idx
  ON class_weekly_point_scores (class_member_id, period_id);
