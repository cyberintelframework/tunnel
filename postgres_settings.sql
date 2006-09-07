--
-- SURFnet IDS database structure
-- Version 1.02.05
-- 23-06-2006
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO idslog;
GRANT USAGE ON SCHEMA public TO nepenthes;
GRANT USAGE ON SCHEMA public TO pofuser;

CREATE TABLE sensors (
    id serial NOT NULL,
    keyname character varying NOT NULL,
    remoteip inet NOT NULL,
    localip inet NOT NULL,
    lastupdate integer,
    laststart integer,
    "action" character varying,
    ssh integer DEFAULT 1,
    status integer,
    uptime integer,
    laststop integer,
    tap character varying,
    tapip inet,
    mac macaddr,
    netconf text,
    organisation integer DEFAULT 0 NOT NULL,
    server integer DEFAULT 1 NOT NULL
);

REVOKE ALL ON TABLE sensors FROM PUBLIC;
GRANT INSERT,SELECT,UPDATE ON TABLE sensors TO idslog;
GRANT SELECT ON TABLE sensors TO nepenthes;

REVOKE ALL ON TABLE sensors_id_seq FROM PUBLIC;
GRANT ALL ON TABLE sensors_id_seq TO idslog;
GRANT INSERT,SELECT,RULE,DELETE,REFERENCES,TRIGGER ON TABLE sensors_id_seq TO nepenthes;

CREATE TABLE attacks (
    id serial NOT NULL,
    "timestamp" integer NOT NULL,
    severity integer NOT NULL,
    source inet NOT NULL,
    sport integer NOT NULL,
    dest inet NOT NULL,
    dport integer NOT NULL,
    sensorid integer NOT NULL
);

REVOKE ALL ON TABLE attacks FROM PUBLIC;
GRANT SELECT ON TABLE attacks TO idslog;
GRANT INSERT,SELECT,UPDATE ON TABLE attacks TO nepenthes;

REVOKE ALL ON TABLE attacks_id_seq FROM PUBLIC;
GRANT ALL ON TABLE attacks_id_seq TO idslog;
GRANT ALL ON TABLE attacks_id_seq TO nepenthes;

CREATE TABLE details (
    id serial NOT NULL,
    attackid integer NOT NULL,
    sensorid integer NOT NULL,
    "type" integer NOT NULL,
    text text NOT NULL
);

REVOKE ALL ON TABLE details FROM PUBLIC;
GRANT SELECT ON TABLE details TO idslog;
GRANT INSERT,SELECT,UPDATE ON TABLE details TO nepenthes;

REVOKE ALL ON TABLE details_id_seq FROM PUBLIC;
GRANT ALL ON TABLE details_id_seq TO idslog;
GRANT ALL ON TABLE details_id_seq TO nepenthes;

CREATE TABLE login (
    id serial NOT NULL,
    username character varying NOT NULL,
    "password" character varying NOT NULL,
    email character varying,
    maillog integer DEFAULT 0,
    alltreshold integer DEFAULT 50,
    owntreshold integer DEFAULT 10,
    timeunit integer DEFAULT 0,
    lastlogin integer,
    organisation integer DEFAULT 0 NOT NULL,
    "access" character varying DEFAULT '000'::character varying NOT NULL
);

REVOKE ALL ON TABLE login FROM PUBLIC;
GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE login TO idslog;

REVOKE ALL ON TABLE login_id_seq FROM PUBLIC;
GRANT ALL ON TABLE login_id_seq TO idslog;

INSERT INTO login (id, username, password, email, organisation, access) VALUES (1, "admin", "21232f297a57a5a743894a0e4a801fc3", "root@localhost", 1, "999");

CREATE TABLE organisations (
    id serial NOT NULL,
    organisation character varying NOT NULL,
    ranges text
);

REVOKE ALL ON TABLE organisations FROM PUBLIC;
GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE organisations TO idslog;

REVOKE ALL ON TABLE organisations_id_seq FROM PUBLIC;
GRANT SELECT,UPDATE ON TABLE organisations_id_seq TO idslog;

INSERT INTO organisations (id, organisation) VALUES (1, "ADMIN");

CREATE TABLE system (
    ip_addr inet NOT NULL,
    name character(128) NOT NULL,
    first_tstamp timestamp with time zone,
    last_tstamp timestamp with time zone NOT NULL
);

REVOKE ALL ON TABLE system FROM PUBLIC;
GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE system TO pofuser;
GRANT SELECT ON TABLE system TO idslog;

CREATE TABLE servers (
    id serial NOT NULL,
    server character varying NOT NULL
);

REVOKE ALL ON TABLE servers FROM PUBLIC;
GRANT INSERT,SELECT,DELETE ON TABLE servers TO idslog;

REVOKE ALL ON TABLE servers_id_seq FROM PUBLIC;
GRANT SELECT,UPDATE ON TABLE servers_id_seq TO idslog;

CREATE TABLE binaries (
    id serial NOT NULL,
    "timestamp" integer,
    bin character varying,
    info character varying,
    scanner character varying
);

REVOKE ALL ON TABLE binaries FROM PUBLIC;
GRANT INSERT,SELECT,UPDATE ON TABLE binaries TO idslog;

REVOKE ALL ON TABLE binaries_id_seq FROM PUBLIC;
GRANT SELECT,UPDATE ON TABLE binaries_id_seq TO idslog;

CREATE TABLE binaries_detail (
    id serial NOT NULL,
    bin character varying,
    fileinfo character varying,
    filesize integer
);

REVOKE ALL ON TABLE binaries_detail FROM PUBLIC;
GRANT INSERT,SELECT ON TABLE binaries_detail TO idslog;

REVOKE ALL ON TABLE binaries_detail_id_seq FROM PUBLIC;
GRANT SELECT,UPDATE ON TABLE binaries_detail_id_seq TO idslog;

CREATE TABLE severity (
    id serial NOT NULL,
    val character(2) NOT NULL,
    txt character varying NOT NULL
);

REVOKE ALL ON TABLE severity FROM PUBLIC;
GRANT SELECT ON TABLE severity TO idslog;

REVOKE ALL ON TABLE severity_id_seq FROM PUBLIC;
GRANT SELECT,UPDATE ON TABLE severity_id_seq TO idslog;

INSERT INTO severity VALUES (1, '0 ', 'Possible malicious attack');
INSERT INTO severity VALUES (2, '1 ', 'Malicious attack');
INSERT INTO severity VALUES (3, '16', 'Malware offered');
INSERT INTO severity VALUES (4, '32', 'Malware downloaded');

CREATE TABLE stats_history (
    id serial NOT NULL,
    sensorid integer NOT NULL,
    "month" integer NOT NULL,
    "year" integer NOT NULL,
    count_possible integer DEFAULT 0,
    count_malicious integer DEFAULT 0,
    count_offered integer DEFAULT 0,
    count_downloaded integer DEFAULT 0,
    "timestamp" integer,
    uptime integer
);

REVOKE ALL ON TABLE stats_history FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON TABLE stats_history TO idslog;

REVOKE ALL ON TABLE stats_history_id_seq FROM PUBLIC;
GRANT SELECT,UPDATE ON TABLE stats_history_id_seq TO idslog;

CREATE TABLE stats_virus (
    id serial NOT NULL,
    name character varying
);

REVOKE ALL ON TABLE stats_virus FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON TABLE stats_virus TO idslog;

REVOKE ALL ON TABLE stats_virus_id_seq FROM PUBLIC;
GRANT SELECT,UPDATE ON TABLE stats_virus_id_seq TO idslog;

CREATE TABLE stats_history_dialogue (
    historyid integer NOT NULL,
    dialogueid integer NOT NULL,
    count integer DEFAULT 1
);

REVOKE ALL ON TABLE stats_history_dialogue FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON TABLE stats_history_dialogue TO idslog;

CREATE TABLE stats_history_virus (
    historyid integer NOT NULL,
    virusid integer NOT NULL,
    count integer DEFAULT 1
);

REVOKE ALL ON TABLE stats_history_virus FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON TABLE stats_history_virus TO idslog;

CREATE TABLE stats_dialogue (
    id serial NOT NULL,
    "desc" character varying,
    url character varying,
    name character varying
);

REVOKE ALL ON TABLE stats_dialogue FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON TABLE stats_dialogue TO idslog;

REVOKE ALL ON TABLE stats_dialogue_id_seq FROM PUBLIC;
GRANT SELECT,UPDATE ON TABLE stats_dialogue_id_seq TO idslog;

CREATE INDEX index_sensors_organisation ON sensors USING btree (organisation);

CREATE INDEX index_binaries ON binaries USING btree (bin);

CREATE INDEX index_attacks_sensorid ON attacks USING btree (sensorid);

CREATE INDEX index_details_attackid ON details USING btree (attackid);

CREATE INDEX index_details_sensorid ON details USING btree (sensorid);

ALTER TABLE ONLY severity
    ADD CONSTRAINT primary_severity PRIMARY KEY (id);

ALTER TABLE ONLY severity
    ADD CONSTRAINT unique_severity UNIQUE (val);

ALTER TABLE ONLY attacks
    ADD CONSTRAINT primary_attacks PRIMARY KEY (id);

ALTER TABLE ONLY sensors
    ADD CONSTRAINT primary_sensors PRIMARY KEY (id);

ALTER TABLE ONLY details
    ADD CONSTRAINT primary_details PRIMARY KEY (id);

ALTER TABLE ONLY login
    ADD CONSTRAINT primary_login PRIMARY KEY (id);

ALTER TABLE ONLY organisations
    ADD CONSTRAINT primary_organisations PRIMARY KEY (id);

ALTER TABLE ONLY organisations
    ADD CONSTRAINT unique_organisation UNIQUE (organisation);

ALTER TABLE ONLY system
    ADD CONSTRAINT system_pkey PRIMARY KEY (ip_addr, name);

ALTER TABLE ONLY servers
    ADD CONSTRAINT primary_servers PRIMARY KEY (id);

ALTER TABLE ONLY binaries
    ADD CONSTRAINT primary_binaries PRIMARY KEY (id);

ALTER TABLE ONLY stats_dialogue
    ADD CONSTRAINT primary_stats_dialogue PRIMARY KEY (id);

ALTER TABLE ONLY stats_history
    ADD CONSTRAINT primary_stats_history PRIMARY KEY (id);

ALTER TABLE ONLY stats_history_dialogue
    ADD CONSTRAINT primary_stats_history_dialogue PRIMARY KEY (historyid, dialogueid);

ALTER TABLE ONLY stats_virus
    ADD CONSTRAINT primary_stats_virus PRIMARY KEY (id);

ALTER TABLE ONLY stats_history_virus
    ADD CONSTRAINT primary_stats_history_virus PRIMARY KEY (historyid, virusid);

ALTER TABLE ONLY details
    ADD CONSTRAINT foreign_attack FOREIGN KEY (attackid) REFERENCES attacks(id);

ALTER TABLE ONLY attacks
    ADD CONSTRAINT foreign_sensor FOREIGN KEY (sensorid) REFERENCES sensors(id);

ALTER TABLE ONLY details
    ADD CONSTRAINT foreign_sensor FOREIGN KEY (sensorid) REFERENCES sensors(id);

ALTER TABLE ONLY stats_history
    ADD CONSTRAINT foreign_stats_history FOREIGN KEY (sensorid) REFERENCES sensors(id);

ALTER TABLE ONLY stats_history_dialogue
    ADD CONSTRAINT foreign_stats_history_dialogue_historyid FOREIGN KEY (historyid) REFERENCES stats_history(id);

ALTER TABLE ONLY stats_history_dialogue
    ADD CONSTRAINT foreign_stats_history_dialogue_foreignid FOREIGN KEY (dialogueid) REFERENCES stats_dialogue(id);

ALTER TABLE ONLY stats_history_virus
    ADD CONSTRAINT foreign_stats_history_virus_historyid FOREIGN KEY (historyid) REFERENCES stats_history(id);

ALTER TABLE ONLY stats_history_virus
    ADD CONSTRAINT foreign_stats_history_virus_virusid FOREIGN KEY (virusid) REFERENCES stats_virus(id);
