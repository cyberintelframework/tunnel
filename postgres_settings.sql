--
-- SURFnet IDS database structure
-- Version 1.02.06
-- 20-07-2006
--

-- Version history
-- 1.02.06 Added serverhash column to the login table
-- 1.02.05 Initial 1.03 release

CREATE TABLE arp_cache (
    id serial NOT NULL,
    "timestamp" integer NOT NULL,
    mac macaddr NOT NULL,
    ip inet NOT NULL,
    sensorid integer NOT NULL,
    query_count integer,
    reply_count integer
);

CREATE TABLE arp_log_poison (
    id serial NOT NULL,
    "timestamp" integer NOT NULL,
    sensorid integer NOT NULL,
    ip inet NOT NULL,
    old_mac macaddr NOT NULL,
    new_mac macaddr NOT NULL
);

CREATE TABLE arp_log_stats (
    id serial NOT NULL,
    "timestamp" integer NOT NULL,
    sensorid integer NOT NULL,
    threshold integer NOT NULL,
    average integer NOT NULL,
    count integer NOT NULL,
    "time" integer NOT NULL,
    "type" integer NOT NULL
);

CREATE TABLE arp_static (
    id serial NOT NULL,
    mac macaddr NOT NULL,
    ip inet NOT NULL,
    sensorid integer NOT NULL
);

CREATE TABLE arp_stats (
    id serial NOT NULL,
    "timestamp" integer NOT NULL,
    sensorid integer NOT NULL,
    queries integer DEFAULT 0 NOT NULL,
    replies integer DEFAULT 0 NOT NULL,
    avg_query integer DEFAULT 0 NOT NULL,
    avg_reply integer DEFAULT 0 NOT NULL,
    query_time integer DEFAULT 0 NOT NULL,
    reply_time integer DEFAULT 0 NOT NULL
);

CREATE TABLE attacks (
    id serial NOT NULL,
    "timestamp" integer NOT NULL,
    severity integer NOT NULL,
    source inet NOT NULL,
    sport integer NOT NULL,
    dest inet NOT NULL,
    dport integer NOT NULL,
    sensorid integer NOT NULL,
    src_mac macaddr
);

CREATE TABLE binaries (
    id serial NOT NULL,
    "timestamp" integer,
    bin character varying,
    info character varying,
    scanner character varying
);

CREATE TABLE binaries_detail (
    id serial NOT NULL,
    bin character varying,
    fileinfo character varying,
    filesize integer
);

CREATE TABLE details (
    id serial NOT NULL,
    attackid integer NOT NULL,
    sensorid integer NOT NULL,
    "type" integer NOT NULL,
    text text NOT NULL
);

CREATE TABLE "login" (
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
    "access" character varying DEFAULT '000'::character varying NOT NULL,
    serverhash character varying
);

CREATE TABLE org_id (
    id serial NOT NULL,
    orgid integer NOT NULL,
    identifier character varying NOT NULL
);

CREATE TABLE organisations (
    id serial NOT NULL,
    organisation character varying NOT NULL,
    ranges text
);

CREATE TABLE report (
    id serial NOT NULL,
    user_id integer NOT NULL,
    enabled boolean NOT NULL,
    email character varying,
    gpg_enabled boolean,
    subject character varying
);

CREATE TABLE report_content (
    id serial NOT NULL,
    report_id integer,
    title character varying,
    "template" integer,
    last_sent integer,
    active boolean,
    sensor_id integer,
    frequency integer,
    "interval" integer,
    priority integer
);

CREATE TABLE report_template_threshold (
    id serial NOT NULL,
    report_content_id integer NOT NULL,
    target integer,
    value integer,
    deviation integer,
    "operator" integer
);

CREATE TABLE search_templates (
    id serial NOT NULL,
    name character varying NOT NULL,
    querystring character varying NOT NULL
);

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
    server integer DEFAULT 1 NOT NULL,
    arp integer DEFAULT 0 NOT NULL,
    arp_threshold_perc integer DEFAULT 0 NOT NULL
);

CREATE TABLE servers (
    id serial NOT NULL,
    server character varying NOT NULL
);

CREATE TABLE severity (
    id integer NOT NULL,
    val character(2) NOT NULL,
    txt character varying NOT NULL
);

CREATE TABLE stats_dialogue (
    id integer DEFAULT nextval(('public.stats_dialogue_id_seq'::text)::regclass) NOT NULL,
    "desc" character varying,
    url character varying,
    name character varying
);

CREATE SEQUENCE stats_dialogue_id_seq
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;

CREATE TABLE stats_history (
    id integer DEFAULT nextval(('public.stats_history_id_seq'::text)::regclass) NOT NULL,
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

CREATE TABLE stats_history_dialogue (
    historyid integer NOT NULL,
    dialogueid integer NOT NULL,
    count integer DEFAULT 1
);

CREATE SEQUENCE stats_history_id_seq
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;

CREATE TABLE stats_history_virus (
    historyid integer NOT NULL,
    virusid integer NOT NULL,
    count integer DEFAULT 1
);

CREATE TABLE stats_virus (
    id integer DEFAULT nextval(('public.stats_virus_id_seq'::text)::regclass) NOT NULL,
    name character varying
);

CREATE SEQUENCE stats_virus_id_seq
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;

CREATE TABLE "system" (
    ip_addr inet NOT NULL,
    name character(128) NOT NULL,
    first_tstamp timestamp with time zone,
    last_tstamp timestamp with time zone NOT NULL
);

ALTER TABLE ONLY arp_cache
    ADD CONSTRAINT primary_arp_cache PRIMARY KEY (id);

ALTER TABLE ONLY arp_static
    ADD CONSTRAINT primary_arp_static PRIMARY KEY (id);

ALTER TABLE ONLY arp_stats
    ADD CONSTRAINT primary_arp_stats PRIMARY KEY (id);

ALTER TABLE ONLY attacks
    ADD CONSTRAINT primary_attacks PRIMARY KEY (id);

ALTER TABLE ONLY binaries
    ADD CONSTRAINT primary_binaries PRIMARY KEY (id);

ALTER TABLE ONLY details
    ADD CONSTRAINT primary_details PRIMARY KEY (id);

ALTER TABLE ONLY "login"
    ADD CONSTRAINT primary_login PRIMARY KEY (id);

ALTER TABLE ONLY org_id
    ADD CONSTRAINT primary_org_id_id PRIMARY KEY (id);

ALTER TABLE ONLY organisations
    ADD CONSTRAINT primary_organisations PRIMARY KEY (id);

ALTER TABLE ONLY tbl_preferences
    ADD CONSTRAINT primary_preferences PRIMARY KEY (id);

ALTER TABLE ONLY report
    ADD CONSTRAINT primary_report PRIMARY KEY (id);

ALTER TABLE ONLY report_content
    ADD CONSTRAINT primary_report_content PRIMARY KEY (id);

ALTER TABLE ONLY report_template_threshold
    ADD CONSTRAINT primary_report_template_threshold PRIMARY KEY (id);

ALTER TABLE ONLY tbl_logs
    ADD CONSTRAINT primary_rid PRIMARY KEY (rid);

ALTER TABLE ONLY tbl_logs_extra
    ADD CONSTRAINT primary_rid_extra PRIMARY KEY (rid);

ALTER TABLE ONLY sensors
    ADD CONSTRAINT primary_sensors PRIMARY KEY (id);

ALTER TABLE ONLY servers
    ADD CONSTRAINT primary_servers PRIMARY KEY (id);

ALTER TABLE ONLY severity
    ADD CONSTRAINT primary_severity PRIMARY KEY (id);

ALTER TABLE ONLY stats_dialogue
    ADD CONSTRAINT primary_stats_dialogue PRIMARY KEY (id);

ALTER TABLE ONLY stats_history
    ADD CONSTRAINT primary_stats_history PRIMARY KEY (id);

ALTER TABLE ONLY stats_history_dialogue
    ADD CONSTRAINT primary_stats_history_dialogue PRIMARY KEY (historyid, dialogueid);

ALTER TABLE ONLY stats_history_virus
    ADD CONSTRAINT primary_stats_history_virus PRIMARY KEY (historyid, virusid);

ALTER TABLE ONLY stats_virus
    ADD CONSTRAINT primary_stats_virus PRIMARY KEY (id);

ALTER TABLE ONLY "system"
    ADD CONSTRAINT system_pkey PRIMARY KEY (ip_addr, name);

ALTER TABLE ONLY org_id
    ADD CONSTRAINT unique_identifier UNIQUE (identifier);

ALTER TABLE ONLY report
    ADD CONSTRAINT unique_report_user_id UNIQUE (user_id);

ALTER TABLE ONLY severity
    ADD CONSTRAINT unique_severity UNIQUE (val);

CREATE INDEX index_attacks_dest ON attacks USING btree (dest);

CREATE UNIQUE INDEX index_attacks_id ON attacks USING btree (id);

ALTER TABLE attacks CLUSTER ON index_attacks_id;

CREATE INDEX index_attacks_sensorid ON attacks USING btree (sensorid);

CREATE INDEX index_attacks_severity ON attacks USING btree (severity);

CREATE INDEX index_attacks_source ON attacks USING btree (source);

CREATE INDEX index_attacks_timestamp ON attacks USING btree ("timestamp");

CREATE INDEX index_binaries ON binaries USING btree (bin);

ALTER TABLE binaries CLUSTER ON index_binaries;

CREATE UNIQUE INDEX index_binaries_detail_bin ON binaries_detail USING btree (bin);

CREATE UNIQUE INDEX index_binaries_detail_id ON binaries_detail USING btree (id);

ALTER TABLE binaries_detail CLUSTER ON index_binaries_detail_id;

CREATE INDEX index_binaries_info ON binaries USING btree (info);

CREATE INDEX index_details_attackid ON details USING btree (attackid);

CREATE UNIQUE INDEX index_details_id ON details USING btree (id);

ALTER TABLE details CLUSTER ON index_details_id;

CREATE INDEX index_details_sensorid ON details USING btree (sensorid);

CREATE UNIQUE INDEX index_sensors_id ON sensors USING btree (id);

ALTER TABLE sensors CLUSTER ON index_sensors_id;

CREATE INDEX index_sensors_organisation ON sensors USING btree (organisation);

ALTER TABLE ONLY details
    ADD CONSTRAINT foreign_attack FOREIGN KEY (attackid) REFERENCES attacks(id);

ALTER TABLE ONLY report_content
    ADD CONSTRAINT foreign_report_content_report_id FOREIGN KEY (report_id) REFERENCES report(id);

ALTER TABLE ONLY report_template_threshold
    ADD CONSTRAINT foreign_report_template_threshold_report_content_id FOREIGN KEY (report_content_id) REFERENCES report_content(id);

ALTER TABLE ONLY report
    ADD CONSTRAINT foreign_report_user_id FOREIGN KEY (user_id) REFERENCES "login"(id);

ALTER TABLE ONLY attacks
    ADD CONSTRAINT foreign_sensor FOREIGN KEY (sensorid) REFERENCES sensors(id);

ALTER TABLE ONLY details
    ADD CONSTRAINT foreign_sensor FOREIGN KEY (sensorid) REFERENCES sensors(id);

ALTER TABLE ONLY stats_history
    ADD CONSTRAINT foreign_stats_history FOREIGN KEY (sensorid) REFERENCES sensors(id);

ALTER TABLE ONLY stats_history_dialogue
    ADD CONSTRAINT foreign_stats_history_dialogue_foreignid FOREIGN KEY (dialogueid) REFERENCES stats_dialogue(id);

ALTER TABLE ONLY stats_history_dialogue
    ADD CONSTRAINT foreign_stats_history_dialogue_historyid FOREIGN KEY (historyid) REFERENCES stats_history(id);

ALTER TABLE ONLY stats_history_virus
    ADD CONSTRAINT foreign_stats_history_virus_historyid FOREIGN KEY (historyid) REFERENCES stats_history(id);

ALTER TABLE ONLY stats_history_virus
    ADD CONSTRAINT foreign_stats_history_virus_virusid FOREIGN KEY (virusid) REFERENCES stats_virus(id);

GRANT INSERT,SELECT,UPDATE ON TABLE arp_cache TO ids;

GRANT SELECT,UPDATE ON TABLE arp_cache_id_seq TO ids;

GRANT INSERT,SELECT,UPDATE ON TABLE arp_log_poison TO ids;

GRANT SELECT,UPDATE ON TABLE arp_log_poison_id_seq TO ids;

GRANT INSERT,SELECT,UPDATE ON TABLE arp_log_stats TO ids;

GRANT SELECT,UPDATE ON TABLE arp_log_stats_id_seq TO ids;

GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE arp_static TO ids;

GRANT SELECT,UPDATE ON TABLE arp_static_id_seq TO ids;

GRANT INSERT,SELECT,UPDATE ON TABLE arp_stats TO ids;

GRANT SELECT,UPDATE ON TABLE arp_stats_id_seq TO ids;

GRANT SELECT,DELETE ON TABLE attacks TO ids;
GRANT INSERT,SELECT,UPDATE ON TABLE attacks TO nepenthes;

GRANT ALL ON TABLE attacks_id_seq TO ids;
GRANT ALL ON TABLE attacks_id_seq TO nepenthes;

GRANT INSERT,SELECT,UPDATE ON TABLE binaries TO ids;

GRANT INSERT,SELECT ON TABLE binaries_detail TO ids;

GRANT SELECT,UPDATE ON TABLE binaries_detail_id_seq TO ids;

GRANT SELECT,UPDATE ON TABLE binaries_id_seq TO ids;

GRANT SELECT ON TABLE details TO ids;
GRANT INSERT,SELECT,UPDATE ON TABLE details TO nepenthes;

GRANT ALL ON TABLE details_id_seq TO ids;
GRANT ALL ON TABLE details_id_seq TO nepenthes;

GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE "login" TO ids;

GRANT ALL ON TABLE login_id_seq TO ids;

GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE org_id TO ids;

GRANT SELECT,UPDATE ON TABLE org_id_id_seq TO ids;

GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE organisations TO ids;

GRANT SELECT,UPDATE ON TABLE organisations_id_seq TO ids;

GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE report TO ids;

GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE report_content TO ids;

GRANT SELECT,UPDATE ON TABLE report_content_id_seq TO ids;

GRANT SELECT,UPDATE ON TABLE report_id_seq TO ids;

GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE report_template_threshold TO ids;

GRANT SELECT,UPDATE ON TABLE report_template_threshold_id_seq TO ids;

GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE search_templates TO ids;

GRANT SELECT,UPDATE ON TABLE search_templates_id_seq TO ids;

GRANT INSERT,SELECT,UPDATE ON TABLE sensors TO ids;
GRANT SELECT ON TABLE sensors TO nepenthes;

GRANT ALL ON TABLE sensors_id_seq TO ids;
GRANT INSERT,SELECT,RULE,DELETE,REFERENCES,TRIGGER ON TABLE sensors_id_seq TO nepenthes;

GRANT INSERT,SELECT,DELETE ON TABLE servers TO ids;

GRANT SELECT,UPDATE ON TABLE servers_id_seq TO ids;

GRANT ALL ON TABLE severity TO ids;

GRANT ALL ON TABLE stats_dialogue TO ids;

GRANT ALL ON TABLE stats_dialogue_id_seq TO ids;

GRANT ALL ON TABLE stats_history TO ids;

GRANT ALL ON TABLE stats_history_dialogue TO ids;

GRANT ALL ON TABLE stats_history_id_seq TO ids;

GRANT ALL ON TABLE stats_history_virus TO ids;

GRANT ALL ON TABLE stats_virus TO ids;

GRANT ALL ON TABLE stats_virus_id_seq TO ids;

GRANT SELECT ON TABLE "system" TO ids;
GRANT INSERT,SELECT,UPDATE,DELETE ON TABLE "system" TO pofuser;
