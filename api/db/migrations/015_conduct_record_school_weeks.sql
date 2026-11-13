ALTER TABLE conduct_records
  ADD COLUMN IF NOT EXISTS week_number INTEGER,
  ADD COLUMN IF NOT EXISTS school_year TEXT;

UPDATE conduct_records AS records
SET week_number = EXTRACT(WEEK FROM records.record_date)::INTEGER,
    school_year = COALESCE(NULLIF(classes.academic_year, ''), EXTRACT(YEAR FROM records.record_date)::TEXT)
FROM classes
WHERE classes.id = records.class_id
  AND (records.week_number IS NULL OR records.school_year IS NULL);

ALTER TABLE conduct_records
  ALTER COLUMN week_number SET NOT NULL,
  ALTER COLUMN school_year SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'conduct_records'::regclass
      AND conname = 'conduct_records_week_number_check'
  ) THEN
    ALTER TABLE conduct_records
      ADD CONSTRAINT conduct_records_week_number_check CHECK (week_number BETWEEN 1 AND 53);
  END IF;
END
$$;

CREATE INDEX IF NOT EXISTS conduct_records_class_week_year_idx
  ON conduct_records (class_id, week_number, school_year);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM conduct_records
    GROUP BY student_member_id, class_id, week_number, school_year
    HAVING COUNT(*) > 1
  ) AND NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = 'conduct_records'::regclass
      AND conname = 'conduct_records_student_class_week_year_key'
  ) THEN
    ALTER TABLE conduct_records
      ADD CONSTRAINT conduct_records_student_class_week_year_key
      UNIQUE (student_member_id, class_id, week_number, school_year);
  END IF;
END
$$;
