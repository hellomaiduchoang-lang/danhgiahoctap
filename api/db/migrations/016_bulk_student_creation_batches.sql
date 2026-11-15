CREATE TABLE bulk_student_creation_batches (
  class_id UUID NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  batch_id UUID NOT NULL,
  request_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (class_id, batch_id)
);
