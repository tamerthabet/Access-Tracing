ALTER TABLE login_audit
  ADD COLUMN source VARCHAR(20) DEFAULT 'web',
  ADD COLUMN event_id VARCHAR(32) DEFAULT NULL,
  ADD COLUMN host VARCHAR(100) DEFAULT NULL,
  ADD COLUMN log_type VARCHAR(50) DEFAULT NULL,
  ADD COLUMN severity VARCHAR(20) DEFAULT NULL,
  ADD COLUMN ti_malicious TINYINT(1) DEFAULT 0,
  ADD COLUMN note TEXT NULL,
  ADD INDEX idx_created_at (created_at),
  ADD INDEX idx_source (source),
  ADD INDEX idx_username (username);
