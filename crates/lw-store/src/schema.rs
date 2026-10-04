pub const MIGRATION_0001: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;
PRAGMA mmap_size=268435456;
PRAGMA page_size=8192;

CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY,
  started_at INTEGER,
  finished_at INTEGER,
  status TEXT,
  rule_pack TEXT,
  rule_pack_hash TEXT,
  profile_json TEXT,
  stats_json TEXT
);

CREATE TABLE IF NOT EXISTS files(
  id INTEGER PRIMARY KEY,
  path TEXT NOT NULL,
  size INTEGER,
  sha256 TEXT,
  mtime INTEGER,
  records_ok INTEGER DEFAULT 0,
  records_err INTEGER DEFAULT 0,
  is_dirty INTEGER,
  first_ts INTEGER,
  last_ts INTEGER,
  error TEXT
);

CREATE TABLE IF NOT EXISTS dict_channel(
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS dict_provider(
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS dict_computer(
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY,
  file_id INTEGER NOT NULL REFERENCES files(id),
  source_type TEXT NOT NULL DEFAULT 'evtx',
  record_id INTEGER NOT NULL,
  ts INTEGER NOT NULL,
  event_id INTEGER NOT NULL,
  channel_id INTEGER NOT NULL REFERENCES dict_channel(id),
  provider_id INTEGER NOT NULL REFERENCES dict_provider(id),
  computer_id INTEGER NOT NULL REFERENCES dict_computer(id),
  level INTEGER,
  user_name TEXT,
  src_ip TEXT,
  logon_type INTEGER,
  fields_json TEXT NOT NULL,
  raw_zstd BLOB
);

CREATE TABLE IF NOT EXISTS detections(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  rule_uid TEXT NOT NULL,
  rule_title TEXT NOT NULL,
  rule_author TEXT,
  rule_source_json TEXT NOT NULL,
  severity INTEGER NOT NULL,
  status TEXT,
  mitre_json TEXT,
  ts INTEGER NOT NULL,
  computer TEXT,
  user_name TEXT,
  kind TEXT NOT NULL,
  group_json TEXT,
  event_count INTEGER NOT NULL DEFAULT 1,
  summary TEXT,
  fp_hint TEXT,
  triage TEXT NOT NULL DEFAULT 'new',
  triage_note TEXT
);

CREATE TABLE IF NOT EXISTS detection_events(
  detection_id INTEGER NOT NULL,
  event_id INTEGER NOT NULL,
  PRIMARY KEY(detection_id, event_id)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS rules(
  rule_uid TEXT PRIMARY KEY,
  title TEXT,
  author TEXT,
  level TEXT,
  status TEXT,
  tags_json TEXT,
  logsource_json TEXT,
  source_json TEXT,
  yaml TEXT,
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS suppressions(
  id INTEGER PRIMARY KEY,
  rule_uid TEXT,
  field TEXT,
  value TEXT,
  note TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS bookmarks(
  id INTEGER PRIMARY KEY,
  event_id INTEGER,
  detection_id INTEGER,
  note TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS gaps(
  id INTEGER PRIMARY KEY,
  file_id INTEGER,
  channel TEXT,
  computer TEXT,
  from_record INTEGER,
  to_record INTEGER,
  from_ts INTEGER,
  to_ts INTEGER,
  reason TEXT
);

CREATE TABLE IF NOT EXISTS logon_summary(
  user_name TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  logon_type INTEGER NOT NULL,
  computer TEXT NOT NULL,
  success_count INTEGER NOT NULL DEFAULT 0,
  fail_count INTEGER NOT NULL DEFAULT 0,
  first_ts INTEGER,
  last_ts INTEGER,
  PRIMARY KEY (user_name, src_ip, logon_type, computer)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS saved_searches(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  query_json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
"#;

pub const FINALIZE_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_eid_channel ON events(event_id, channel_id);
CREATE INDEX IF NOT EXISTS idx_events_computer_ts ON events(computer_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_user_ts ON events(user_name, ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_file_record ON events(file_id, record_id);
CREATE INDEX IF NOT EXISTS idx_detections_sev_ts ON detections(severity, ts);
CREATE INDEX IF NOT EXISTS idx_detections_rule ON detections(rule_uid);
CREATE INDEX IF NOT EXISTS idx_detections_computer_ts ON detections(computer, ts);
CREATE INDEX IF NOT EXISTS idx_detections_user_ts ON detections(user_name, ts);
"#;

pub const FTS_CREATE: &str = r#"
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
  text,
  content='',
  tokenize='unicode61 remove_diacritics 2'
);
"#;
