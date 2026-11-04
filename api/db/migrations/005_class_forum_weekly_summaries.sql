CREATE TABLE class_forum_posts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  author_member_id UUID NOT NULL,
  week_start DATE NOT NULL,
  week_end DATE NOT NULL,
  title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
  message TEXT NOT NULL DEFAULT '' CHECK (length(message) <= 2000),
  score_snapshot JSONB NOT NULL CHECK (jsonb_typeof(score_snapshot) = 'array'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (week_end >= week_start AND week_end - week_start < 7),
  FOREIGN KEY (class_id, author_member_id) REFERENCES class_members(class_id, id) ON DELETE CASCADE,
  UNIQUE (class_id, week_start)
);

CREATE INDEX class_forum_posts_feed_idx ON class_forum_posts (class_id, week_start DESC, created_at DESC);
