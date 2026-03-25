-- Project Mycelium – PostgreSQL / TimescaleDB Schema

-- ─── Extensions ──────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Connections Log ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS connections (
    id          UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    spore_id    TEXT        NOT NULL,
    protocol    TEXT        NOT NULL,       -- mqtt | modbus | http
    source_ip   INET        NOT NULL,
    source_port INTEGER,
    uri         TEXT,
    payload     JSONB,
    timestamp   TIMESTAMPTZ DEFAULT NOW()
);
SELECT create_hypertable('connections', 'timestamp', if_not_exists => TRUE);
CREATE INDEX ON connections (source_ip, timestamp DESC);
CREATE INDEX ON connections (spore_id, timestamp DESC);

-- ─── Threat Alerts ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_alerts (
    id              UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_ip       INET        NOT NULL,
    detector_spore  TEXT        NOT NULL,
    threat_type     TEXT        NOT NULL,   -- port_scan | brute_force | exploit_attempt | recon
    severity        FLOAT       NOT NULL DEFAULT 0.0,  -- 0.0 – 1.0
    confidence      FLOAT       NOT NULL DEFAULT 0.0,
    raw_payload     JSONB,
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);
SELECT create_hypertable('threat_alerts', 'timestamp', if_not_exists => TRUE);
CREATE INDEX ON threat_alerts (source_ip, timestamp DESC);
CREATE INDEX ON threat_alerts (severity DESC, timestamp DESC);

-- ─── Threat Level State ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threat_level (
    id          SERIAL      PRIMARY KEY,
    level       TEXT        NOT NULL CHECK (level IN ('low','medium','high')),
    changed_at  TIMESTAMPTZ DEFAULT NOW(),
    changed_by  TEXT        DEFAULT 'ai_engine'
);
INSERT INTO threat_level (level) VALUES ('low');

-- ─── Spore Registry ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS spores (
    spore_id        TEXT        PRIMARY KEY,
    spore_type      TEXT        NOT NULL,
    ip_address      INET,
    protocols       TEXT[]      DEFAULT '{}',
    banner          TEXT,
    status          TEXT        DEFAULT 'active',  -- active | sleeping | destroyed
    spawned_at      TIMESTAMPTZ DEFAULT NOW(),
    last_heartbeat  TIMESTAMPTZ DEFAULT NOW(),
    is_dynamic      BOOLEAN     DEFAULT FALSE       -- TRUE = AI-spawned at runtime
);

-- ─── Canary Tokens ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS canary_tokens (
    token_id        UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    token_value     TEXT        UNIQUE NOT NULL,
    token_type      TEXT        NOT NULL,   -- url | email | dns
    spore_id        TEXT        REFERENCES spores(spore_id),
    embedded_in     TEXT,                  -- e.g. "config.json"
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    triggered       BOOLEAN     DEFAULT FALSE,
    triggered_at    TIMESTAMPTZ
);

-- ─── Canary Hits ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS canary_hits (
    id          UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    token_id    UUID        REFERENCES canary_tokens(token_id),
    source_ip   INET,
    user_agent  TEXT,
    referer     TEXT,
    extra       JSONB,
    timestamp   TIMESTAMPTZ DEFAULT NOW()
);
SELECT create_hypertable('canary_hits', 'timestamp', if_not_exists => TRUE);

-- ─── Response Actions Log ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS response_actions (
    id          UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    action      TEXT        NOT NULL,   -- banner_change | spawn_spore | fingerprint_rotate
    triggered_by TEXT,
    details     JSONB,
    timestamp   TIMESTAMPTZ DEFAULT NOW()
);
SELECT create_hypertable('response_actions', 'timestamp', if_not_exists => TRUE);

-- ─── Deception Score View ─────────────────────────────────────────────────────
CREATE OR REPLACE VIEW deception_score AS
SELECT
    COUNT(DISTINCT c.source_ip)         AS unique_attackers,
    COUNT(c.id)                         AS total_interactions,
    COUNT(ch.id)                        AS canary_triggers,
    COUNT(ta.id)                        AS threat_alerts_fired,
    COUNT(CASE WHEN ta.severity >= 0.7 THEN 1 END) AS high_severity_events,
    -- Time wasted: each interaction = ~30s of attacker time (heuristic)
    COUNT(c.id) * 30                    AS estimated_attacker_seconds_wasted
FROM connections c
LEFT JOIN canary_hits ch   ON ch.timestamp > NOW() - INTERVAL '24 hours'
LEFT JOIN threat_alerts ta ON ta.timestamp > NOW() - INTERVAL '24 hours';
