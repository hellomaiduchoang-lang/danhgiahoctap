CREATE SEQUENCE student_account_code_seq START WITH 1;

SELECT setval(
  'student_account_code_seq',
  COALESCE((
    SELECT MAX((regexp_match(UPPER(student_number), '^HS([0-9]+)$'))[1]::BIGINT)
    FROM users
    WHERE student_number IS NOT NULL
      AND regexp_match(UPPER(student_number), '^HS([0-9]+)$') IS NOT NULL
  ), 0) + 1,
  FALSE
);
