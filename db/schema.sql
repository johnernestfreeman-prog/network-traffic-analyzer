DROP TABLE IF EXISTS packet_events;

CREATE TABLE packet_events (
    id BIGSERIAL PRIMARY KEY,
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    source_port INTEGER,
    dest_port INTEGER,
    protocol VARCHAR(20) NOT NULL,
    length_bytes INTEGER NOT NULL,
    tcp_flags VARCHAR(20),
    timestamp_unix_ms BIGINT NOT NULL,
    alerts TEXT[],
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_packet_events_timestamp ON packet_events(timestamp_unix_ms);
CREATE INDEX idx_packet_events_source_ip ON packet_events(source_ip);
CREATE INDEX idx_packet_events_protocol ON packet_events(protocol);
