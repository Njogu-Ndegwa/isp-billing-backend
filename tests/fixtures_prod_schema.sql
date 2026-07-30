--
-- PostgreSQL database dump
--

\restrict TIkuTftwQGI9FIC0dTq7vm1lGyA8r9Tefct4cAx3FaDqRbGyUX4qrFjt1SFvBRr

-- Dumped from database version 15.15
-- Dumped by pg_dump version 15.15

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: accesscredstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.accesscredstatus AS ENUM (
    'active',
    'revoked'
);


--
-- Name: adbadgetype; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.adbadgetype AS ENUM (
    'HOT',
    'NEW',
    'SALE'
);


--
-- Name: adclicktype; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.adclicktype AS ENUM (
    'VIEW_DETAILS',
    'CALL',
    'WHATSAPP'
);


--
-- Name: b2btransactionstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.b2btransactionstatus AS ENUM (
    'pending',
    'completed',
    'failed',
    'timed_out',
    'timeout'
);


--
-- Name: c2btransactionstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.c2btransactionstatus AS ENUM (
    'processed',
    'unmatched',
    'rejected',
    'duplicate'
);


--
-- Name: collectionmode; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.collectionmode AS ENUM (
    'direct',
    'system_collected'
);


--
-- Name: connectiontype; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.connectiontype AS ENUM (
    'HOTSPOT',
    'PPPOE',
    'STATIC_IP',
    'pppoe'
);


--
-- Name: customerstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.customerstatus AS ENUM (
    'ACTIVE',
    'INACTIVE',
    'PENDING'
);


--
-- Name: devicetype; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.devicetype AS ENUM (
    'tv',
    'console',
    'laptop',
    'iot',
    'other'
);


--
-- Name: durationunit; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.durationunit AS ENUM (
    'MINUTES',
    'HOURS',
    'DAYS'
);


--
-- Name: failuresource; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.failuresource AS ENUM (
    'client',
    'mpesa_api',
    'server',
    'timeout'
);


--
-- Name: feedbackkind; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.feedbackkind AS ENUM (
    'bug',
    'idea'
);


--
-- Name: feedbackstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.feedbackstatus AS ENUM (
    'new',
    'under_review',
    'planned',
    'in_progress',
    'fixed',
    'declined',
    'duplicate',
    'spam'
);


--
-- Name: fupaction; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.fupaction AS ENUM (
    'throttle',
    'block',
    'notify_only'
);


--
-- Name: invoicestatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.invoicestatus AS ENUM (
    'pending',
    'paid',
    'overdue',
    'waived'
);


--
-- Name: leadactivitytype; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.leadactivitytype AS ENUM (
    'note',
    'call',
    'dm',
    'email',
    'meeting',
    'stage_change',
    'followup_completed',
    'other'
);


--
-- Name: leadstage; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.leadstage AS ENUM (
    'new_lead',
    'contacted',
    'talking',
    'installation_help',
    'signed_up',
    'paying',
    'churned',
    'lost'
);


--
-- Name: mpesatransactionstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.mpesatransactionstatus AS ENUM (
    'pending',
    'completed',
    'failed',
    'expired'
);


--
-- Name: mtnmomotransactionstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.mtnmomotransactionstatus AS ENUM (
    'pending',
    'successful',
    'failed'
);


--
-- Name: paymentmethod; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.paymentmethod AS ENUM (
    'CASH',
    'MOBILE_MONEY',
    'BANK_TRANSFER',
    'CARD',
    'OTHER',
    'voucher'
);


--
-- Name: paymentmethodtype; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.paymentmethodtype AS ENUM (
    'bank_account',
    'paybill',
    'paybill_with_keys'
);


--
-- Name: paymentstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.paymentstatus AS ENUM (
    'PENDING',
    'COMPLETED',
    'FAILED',
    'REFUNDED'
);


--
-- Name: plantype; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.plantype AS ENUM (
    'regular',
    'emergency',
    'special_offer'
);


--
-- Name: provisioningattemptentrypoint; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.provisioningattemptentrypoint AS ENUM (
    'hotspot_payment',
    'hotspot_reconciliation',
    'voucher_direct_api',
    'manual_transaction_provision',
    'subscription_share'
);


--
-- Name: provisioningattemptsource; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.provisioningattemptsource AS ENUM (
    'mpesa_transaction',
    'customer_payment',
    'subscription_share'
);


--
-- Name: provisioningonlinestate; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.provisioningonlinestate AS ENUM (
    'unknown',
    'offline',
    'online'
);


--
-- Name: provisioningstate; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.provisioningstate AS ENUM (
    'scheduled',
    'in_progress',
    'retry_pending',
    'router_updated',
    'failed'
);


--
-- Name: provisioningtokenstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.provisioningtokenstatus AS ENUM (
    'pending',
    'provisioned',
    'expired'
);


--
-- Name: resellerpaymentmethodtype; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.resellerpaymentmethodtype AS ENUM (
    'bank_account',
    'mpesa_paybill',
    'mpesa_paybill_with_keys',
    'zenopay',
    'mtn_momo',
    'mpesa_till'
);


--
-- Name: routerauthmethod; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.routerauthmethod AS ENUM (
    'DIRECT_API',
    'RADIUS'
);


--
-- Name: routerlogseverity; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.routerlogseverity AS ENUM (
    'info',
    'warning',
    'error'
);


--
-- Name: shoporderpaymentstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.shoporderpaymentstatus AS ENUM (
    'unpaid',
    'paid',
    'refunded'
);


--
-- Name: shoporderstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.shoporderstatus AS ENUM (
    'pending',
    'confirmed',
    'processing',
    'shipped',
    'delivered',
    'cancelled'
);


--
-- Name: smscampaignstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.smscampaignstatus AS ENUM (
    'queued',
    'sending',
    'completed',
    'partial',
    'failed',
    'canceled'
);


--
-- Name: smscreditorderstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.smscreditorderstatus AS ENUM (
    'pending',
    'completed',
    'failed',
    'expired'
);


--
-- Name: smscredittxnkind; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.smscredittxnkind AS ENUM (
    'purchase',
    'send_debit',
    'refund',
    'admin_adjustment'
);


--
-- Name: smsmessagekind; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.smsmessagekind AS ENUM (
    'reseller_to_customer',
    'admin_to_reseller'
);


--
-- Name: smsmessagestatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.smsmessagestatus AS ENUM (
    'queued',
    'sent',
    'delivered',
    'failed'
);


--
-- Name: subscriptionpaymentstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.subscriptionpaymentstatus AS ENUM (
    'pending',
    'completed',
    'failed'
);


--
-- Name: subscriptionstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.subscriptionstatus AS ENUM (
    'active',
    'inactive',
    'trial',
    'suspended'
);


--
-- Name: unmatchedc2breason; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.unmatchedc2breason AS ENUM (
    'unknown_account',
    'amount_too_low',
    'wrong_reseller',
    'invalid_luhn'
);


--
-- Name: userrole; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.userrole AS ENUM (
    'ADMIN',
    'RESELLER'
);


--
-- Name: voucherstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.voucherstatus AS ENUM (
    'available',
    'redeemed',
    'expired',
    'disabled'
);


--
-- Name: vouchertype; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.vouchertype AS ENUM (
    'sale',
    'compensation'
);


--
-- Name: zenopaytransactionstatus; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.zenopaytransactionstatus AS ENUM (
    'pending',
    'completed',
    'failed'
);


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: access_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.access_credentials (
    id integer NOT NULL,
    user_id integer NOT NULL,
    router_id integer NOT NULL,
    username character varying(64) NOT NULL,
    password character varying(128) NOT NULL,
    rate_limit character varying(50),
    data_cap_mb bigint,
    label character varying(255),
    status public.accesscredstatus DEFAULT 'active'::public.accesscredstatus NOT NULL,
    bound_mac_address character varying(50),
    bound_at timestamp without time zone,
    last_login_at timestamp without time zone,
    last_seen_at timestamp without time zone,
    last_seen_ip character varying(45),
    total_bytes_in bigint DEFAULT '0'::bigint NOT NULL,
    total_bytes_out bigint DEFAULT '0'::bigint NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    revoked_at timestamp without time zone
);


--
-- Name: access_credentials_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.access_credentials_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: access_credentials_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.access_credentials_id_seq OWNED BY public.access_credentials.id;


--
-- Name: ad_clicks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ad_clicks (
    id integer NOT NULL,
    ad_id integer NOT NULL,
    click_type public.adclicktype NOT NULL,
    device_id character varying(100),
    user_agent character varying(500),
    session_id character varying(100),
    referrer character varying(100),
    mac_address character varying(50),
    created_at timestamp without time zone
);


--
-- Name: ad_clicks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ad_clicks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ad_clicks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ad_clicks_id_seq OWNED BY public.ad_clicks.id;


--
-- Name: ad_impressions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ad_impressions (
    id integer NOT NULL,
    device_id character varying(100),
    session_id character varying(100),
    placement character varying(100),
    ad_ids json NOT NULL,
    created_at timestamp without time zone
);


--
-- Name: ad_impressions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ad_impressions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ad_impressions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ad_impressions_id_seq OWNED BY public.ad_impressions.id;


--
-- Name: ads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ads (
    id integer NOT NULL,
    advertiser_id integer NOT NULL,
    title character varying(150) NOT NULL,
    description character varying(500),
    image_url character varying(500) NOT NULL,
    seller_name character varying(100) NOT NULL,
    seller_location character varying(200),
    phone_number character varying(20) NOT NULL,
    whatsapp_number character varying(20),
    price character varying(50),
    price_value double precision,
    badge_type public.adbadgetype,
    badge_text character varying(50),
    category character varying(50),
    is_active boolean,
    priority integer,
    views_count integer,
    clicks_count integer,
    created_at timestamp without time zone,
    expires_at timestamp without time zone
);


--
-- Name: ads_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ads_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ads_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ads_id_seq OWNED BY public.ads.id;


--
-- Name: advertisers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.advertisers (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    business_name character varying(150),
    phone_number character varying(20) NOT NULL,
    email character varying(100),
    is_active boolean,
    created_at timestamp without time zone
);


--
-- Name: advertisers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.advertisers_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: advertisers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.advertisers_id_seq OWNED BY public.advertisers.id;


--
-- Name: agent_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_runs (
    id integer NOT NULL,
    agent character varying(64) NOT NULL,
    work_item_id integer,
    outcome character varying(32) DEFAULT 'running'::character varying NOT NULL,
    summary character varying(4000),
    tokens integer,
    session_url character varying(500),
    session_surface character varying(32),
    started_at timestamp without time zone,
    ended_at timestamp without time zone,
    heartbeat_at timestamp without time zone
);


--
-- Name: agent_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_runs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_runs_id_seq OWNED BY public.agent_runs.id;


--
-- Name: agent_schedules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_schedules (
    id integer NOT NULL,
    name character varying(120) NOT NULL,
    agent character varying(64) NOT NULL,
    description character varying(500),
    cadence character varying(120),
    cron_expr character varying(120),
    expected_interval_minutes integer,
    enabled boolean DEFAULT true NOT NULL,
    surface character varying(32),
    last_run_at timestamp without time zone,
    last_outcome character varying(32),
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: agent_schedules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_schedules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_schedules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_schedules_id_seq OWNED BY public.agent_schedules.id;


--
-- Name: app_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.app_settings (
    key character varying(100) NOT NULL,
    value character varying(500) NOT NULL,
    updated_at timestamp without time zone
);


--
-- Name: approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.approvals (
    id integer NOT NULL,
    kind character varying(32) NOT NULL,
    subject character varying(300) NOT NULL,
    payload character varying(4000),
    proposed_by character varying(64) DEFAULT 'agent'::character varying NOT NULL,
    status character varying(32) DEFAULT 'pending'::character varying NOT NULL,
    work_item_id integer,
    note character varying(500),
    created_at timestamp without time zone,
    decided_at timestamp without time zone,
    decided_by character varying(64)
);


--
-- Name: approvals_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.approvals_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: approvals_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.approvals_id_seq OWNED BY public.approvals.id;


--
-- Name: b2b_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.b2b_transactions (
    id integer NOT NULL,
    reseller_id integer NOT NULL,
    conversation_id character varying(255),
    originator_conversation_id character varying(255),
    amount double precision NOT NULL,
    fee double precision NOT NULL,
    net_amount double precision NOT NULL,
    party_a character varying(20) NOT NULL,
    party_b character varying(20) NOT NULL,
    account_reference character varying(255),
    command_id character varying(50) NOT NULL,
    remarks character varying(255),
    status public.b2btransactionstatus NOT NULL,
    result_code character varying(50),
    result_desc character varying(500),
    transaction_id character varying(255),
    payout_id integer,
    charge_id integer,
    created_at timestamp without time zone,
    completed_at timestamp without time zone,
    triggered_by character varying(20)
);


--
-- Name: b2b_transactions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.b2b_transactions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: b2b_transactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.b2b_transactions_id_seq OWNED BY public.b2b_transactions.id;


--
-- Name: bandwidth_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bandwidth_snapshots (
    id integer NOT NULL,
    router_id integer,
    total_upload_bps bigint,
    total_download_bps bigint,
    avg_upload_bps double precision,
    avg_download_bps double precision,
    active_queues integer,
    active_sessions integer,
    interface_rx_bytes bigint,
    interface_tx_bytes bigint,
    recorded_at timestamp without time zone,
    active_hotspot_users integer DEFAULT 0 NOT NULL,
    hotspot_upload_bytes bigint DEFAULT 0 NOT NULL,
    hotspot_download_bytes bigint DEFAULT 0 NOT NULL,
    pppoe_upload_bytes bigint DEFAULT 0 NOT NULL,
    pppoe_download_bytes bigint DEFAULT 0 NOT NULL
);


--
-- Name: bandwidth_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.bandwidth_snapshots_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: bandwidth_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.bandwidth_snapshots_id_seq OWNED BY public.bandwidth_snapshots.id;


--
-- Name: c2b_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.c2b_transactions (
    id integer NOT NULL,
    trans_id character varying(64) NOT NULL,
    bill_ref_number character varying(64),
    trans_amount double precision NOT NULL,
    msisdn character varying(128),
    business_shortcode character varying(20),
    payload_json json,
    status public.c2btransactionstatus NOT NULL,
    matched_customer_id integer,
    matched_reseller_id integer,
    received_at timestamp without time zone NOT NULL,
    processed_at timestamp without time zone
);


--
-- Name: c2b_transactions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.c2b_transactions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: c2b_transactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.c2b_transactions_id_seq OWNED BY public.c2b_transactions.id;


--
-- Name: customer_payments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customer_payments (
    id integer NOT NULL,
    customer_id integer,
    reseller_id integer NOT NULL,
    amount double precision NOT NULL,
    payment_method public.paymentmethod NOT NULL,
    payment_reference character varying(100),
    payment_date timestamp without time zone,
    days_paid_for integer NOT NULL,
    status public.paymentstatus,
    notes character varying(500),
    lipay_tx_no character varying(255),
    created_at timestamp without time zone,
    collection_mode public.collectionmode,
    customer_name character varying(255),
    counts_as_revenue boolean DEFAULT true NOT NULL,
    port_name character varying(64),
    plan_id integer
);


--
-- Name: customer_payments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.customer_payments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: customer_payments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.customer_payments_id_seq OWNED BY public.customer_payments.id;


--
-- Name: customer_ratings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customer_ratings (
    id integer NOT NULL,
    customer_id integer,
    phone character varying NOT NULL,
    rating integer NOT NULL,
    comment character varying(500),
    service_quality integer,
    support_rating integer,
    value_for_money integer,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    latitude double precision,
    longitude double precision
);


--
-- Name: customer_ratings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.customer_ratings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: customer_ratings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.customer_ratings_id_seq OWNED BY public.customer_ratings.id;


--
-- Name: customer_usage_periods; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customer_usage_periods (
    id integer NOT NULL,
    customer_id integer NOT NULL,
    period_start timestamp without time zone NOT NULL,
    period_end timestamp without time zone NOT NULL,
    upload_bytes bigint DEFAULT 0 NOT NULL,
    download_bytes bigint DEFAULT 0 NOT NULL,
    total_bytes bigint DEFAULT 0 NOT NULL,
    cap_mb_snapshot bigint,
    fup_action_snapshot public.fupaction,
    fup_triggered_at timestamp without time zone,
    fup_action_taken public.fupaction,
    fup_reverted_at timestamp without time zone,
    closed_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: customer_usage_periods_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.customer_usage_periods_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: customer_usage_periods_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.customer_usage_periods_id_seq OWNED BY public.customer_usage_periods.id;


--
-- Name: customers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.customers (
    id integer NOT NULL,
    name character varying,
    phone character varying NOT NULL,
    mac_address character varying,
    pppoe_username character varying,
    pppoe_password character varying,
    static_ip character varying,
    status public.customerstatus NOT NULL,
    expiry timestamp without time zone,
    plan_id integer,
    user_id integer,
    created_at timestamp without time zone,
    router_id integer,
    pending_update_data json,
    latitude double precision,
    longitude double precision,
    location_captured_at timestamp without time zone,
    account_number character varying(8),
    wallet_credit_kes integer DEFAULT 0 NOT NULL,
    subscription_owner_id integer,
    CONSTRAINT ck_customers_wallet_credit_non_negative CHECK ((wallet_credit_kes >= 0))
);


--
-- Name: customers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.customers_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: customers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.customers_id_seq OWNED BY public.customers.id;


--
-- Name: device_pairings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_pairings (
    id integer NOT NULL,
    customer_id integer NOT NULL,
    device_mac character varying NOT NULL,
    device_name character varying(100),
    device_type public.devicetype DEFAULT 'tv'::public.devicetype NOT NULL,
    router_id integer NOT NULL,
    plan_id integer,
    is_active boolean DEFAULT true,
    provisioned_at timestamp without time zone,
    expires_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    subscription_owner_customer_id integer,
    is_subscription_share boolean DEFAULT false NOT NULL
);


--
-- Name: device_pairings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.device_pairings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: device_pairings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.device_pairings_id_seq OWNED BY public.device_pairings.id;


--
-- Name: feedback_comments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.feedback_comments (
    id integer NOT NULL,
    post_id integer NOT NULL,
    user_id integer NOT NULL,
    body character varying(2000) NOT NULL,
    is_admin boolean DEFAULT false NOT NULL,
    created_at timestamp without time zone
);


--
-- Name: feedback_comments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.feedback_comments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: feedback_comments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.feedback_comments_id_seq OWNED BY public.feedback_comments.id;


--
-- Name: feedback_posts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.feedback_posts (
    id integer NOT NULL,
    user_id integer NOT NULL,
    kind public.feedbackkind NOT NULL,
    title character varying(200) NOT NULL,
    body character varying(5000) NOT NULL,
    status public.feedbackstatus DEFAULT 'new'::public.feedbackstatus NOT NULL,
    upvotes integer DEFAULT 0 NOT NULL,
    downvotes integer DEFAULT 0 NOT NULL,
    comment_count integer DEFAULT 0 NOT NULL,
    duplicate_of_id integer,
    ai_triaged_at timestamp without time zone,
    ai_spam boolean,
    ai_kind character varying(16),
    ai_severity integer,
    ai_summary character varying(300),
    ai_affected_area character varying(60),
    ai_duplicate_of_id integer,
    ai_raw json,
    ai_error character varying(255),
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: feedback_posts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.feedback_posts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: feedback_posts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.feedback_posts_id_seq OWNED BY public.feedback_posts.id;


--
-- Name: feedback_votes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.feedback_votes (
    id integer NOT NULL,
    post_id integer NOT NULL,
    user_id integer NOT NULL,
    value integer NOT NULL,
    created_at timestamp without time zone
);


--
-- Name: feedback_votes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.feedback_votes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: feedback_votes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.feedback_votes_id_seq OWNED BY public.feedback_votes.id;


--
-- Name: growth_targets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.growth_targets (
    id integer NOT NULL,
    target_id character varying(100) NOT NULL,
    label character varying(255) NOT NULL,
    target_value double precision NOT NULL,
    unit character varying(50) NOT NULL,
    period character varying(100) NOT NULL,
    inverse boolean DEFAULT false NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: growth_targets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.growth_targets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: growth_targets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.growth_targets_id_seq OWNED BY public.growth_targets.id;


--
-- Name: lead_activities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lead_activities (
    id integer NOT NULL,
    lead_id integer NOT NULL,
    activity_type public.leadactivitytype NOT NULL,
    description character varying(2000),
    old_stage character varying(50),
    new_stage character varying(50),
    created_by integer NOT NULL,
    created_at timestamp without time zone
);


--
-- Name: lead_activities_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.lead_activities_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: lead_activities_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.lead_activities_id_seq OWNED BY public.lead_activities.id;


--
-- Name: lead_follow_ups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lead_follow_ups (
    id integer NOT NULL,
    lead_id integer NOT NULL,
    title character varying(255) NOT NULL,
    due_at timestamp without time zone NOT NULL,
    is_completed boolean DEFAULT false NOT NULL,
    completed_at timestamp without time zone,
    created_by integer NOT NULL,
    created_at timestamp without time zone
);


--
-- Name: lead_follow_ups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.lead_follow_ups_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: lead_follow_ups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.lead_follow_ups_id_seq OWNED BY public.lead_follow_ups.id;


--
-- Name: lead_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lead_sources (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    description character varying(255),
    is_active boolean DEFAULT true NOT NULL,
    user_id integer NOT NULL,
    created_at timestamp without time zone
);


--
-- Name: lead_sources_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.lead_sources_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: lead_sources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.lead_sources_id_seq OWNED BY public.lead_sources.id;


--
-- Name: leads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.leads (
    id integer NOT NULL,
    user_id integer NOT NULL,
    name character varying(255) NOT NULL,
    phone character varying(20),
    email character varying(255),
    social_platform character varying(50),
    social_handle character varying(100),
    source_id integer,
    source_detail character varying(500),
    stage public.leadstage DEFAULT 'new_lead'::public.leadstage NOT NULL,
    stage_changed_at timestamp without time zone,
    next_followup_at timestamp without time zone,
    notes character varying(2000),
    converted_user_id integer,
    lost_reason character varying(500),
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: leads_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.leads_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: leads_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.leads_id_seq OWNED BY public.leads.id;


--
-- Name: message_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_templates (
    id integer NOT NULL,
    user_id integer NOT NULL,
    name character varying(120) NOT NULL,
    body character varying(1000) NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: message_templates_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.message_templates_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: message_templates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.message_templates_id_seq OWNED BY public.message_templates.id;


--
-- Name: messaging_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.messaging_settings (
    id integer NOT NULL,
    price_per_sms_kes numeric(6,2) DEFAULT 0.50 NOT NULL,
    min_purchase_credits integer DEFAULT 10 NOT NULL,
    sender_id character varying(20),
    provider character varying(50) DEFAULT 'talksasa'::character varying NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    message_retention_days integer DEFAULT 60 NOT NULL,
    bundles json,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    welcome_enabled boolean DEFAULT true NOT NULL,
    welcome_subject character varying(200),
    welcome_message_body character varying(2000),
    welcome_support_phone character varying(20)
);


--
-- Name: messaging_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.messaging_settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: messaging_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.messaging_settings_id_seq OWNED BY public.messaging_settings.id;


--
-- Name: mpesa_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mpesa_transactions (
    id integer NOT NULL,
    checkout_request_id character varying(255) NOT NULL,
    phone_number character varying(20) NOT NULL,
    amount numeric(10,2) NOT NULL,
    reference character varying(255) NOT NULL,
    lipay_tx_no character varying(255),
    status public.mpesatransactionstatus,
    customer_id integer,
    merchant_request_id character varying(255),
    mpesa_receipt_number character varying(255),
    transaction_date timestamp without time zone,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    result_code character varying(50),
    result_desc character varying(500),
    failure_source public.failuresource,
    plan_id integer
);


--
-- Name: mpesa_transactions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mpesa_transactions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mpesa_transactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mpesa_transactions_id_seq OWNED BY public.mpesa_transactions.id;


--
-- Name: mtn_momo_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mtn_momo_transactions (
    id integer NOT NULL,
    reference_id character varying(64) NOT NULL,
    external_id character varying(64),
    reseller_id integer NOT NULL,
    customer_id integer,
    amount numeric(10,2) NOT NULL,
    currency character varying(10) NOT NULL,
    phone character varying(20) NOT NULL,
    status public.mtnmomotransactionstatus DEFAULT 'pending'::public.mtnmomotransactionstatus NOT NULL,
    financial_transaction_id character varying(128),
    reason_code character varying(100),
    reason_message character varying(500),
    target_environment character varying(50) NOT NULL,
    payer_message character varying(160),
    payee_note character varying(160),
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: mtn_momo_transactions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mtn_momo_transactions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mtn_momo_transactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mtn_momo_transactions_id_seq OWNED BY public.mtn_momo_transactions.id;


--
-- Name: password_reset_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.password_reset_tokens (
    id integer NOT NULL,
    user_id integer NOT NULL,
    token_hash character varying(64) NOT NULL,
    created_at timestamp without time zone NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    used_at timestamp without time zone
);


--
-- Name: password_reset_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.password_reset_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: password_reset_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.password_reset_tokens_id_seq OWNED BY public.password_reset_tokens.id;


--
-- Name: payments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.payments (
    id integer NOT NULL,
    customer_id integer NOT NULL,
    amount integer NOT NULL,
    days_paid_for integer NOT NULL,
    paid_on timestamp without time zone
);


--
-- Name: payments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.payments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: payments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.payments_id_seq OWNED BY public.payments.id;


--
-- Name: plans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.plans (
    id integer NOT NULL,
    name character varying NOT NULL,
    speed character varying NOT NULL,
    price integer NOT NULL,
    duration_value integer NOT NULL,
    duration_unit public.durationunit NOT NULL,
    connection_type public.connectiontype NOT NULL,
    user_id integer NOT NULL,
    router_profile character varying,
    created_at timestamp without time zone,
    plan_type public.plantype DEFAULT 'regular'::public.plantype NOT NULL,
    is_hidden boolean DEFAULT false NOT NULL,
    badge_text character varying(100),
    original_price integer,
    valid_until timestamp without time zone,
    data_cap_mb bigint,
    fup_action public.fupaction,
    fup_throttle_profile character varying(100),
    max_shared_users integer DEFAULT 1 NOT NULL
);


--
-- Name: plans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.plans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: plans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.plans_id_seq OWNED BY public.plans.id;


--
-- Name: portal_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.portal_settings (
    id integer NOT NULL,
    user_id integer NOT NULL,
    color_theme character varying(50) DEFAULT 'ocean_blue'::character varying NOT NULL,
    header_style character varying(50) DEFAULT 'standard'::character varying NOT NULL,
    show_ads boolean DEFAULT true NOT NULL,
    show_welcome_banner boolean DEFAULT true NOT NULL,
    welcome_title character varying(200),
    welcome_subtitle character varying(500),
    company_logo_url character varying(500),
    header_bg_image_url character varying(500),
    footer_text character varying(500),
    portal_support_phone character varying(20),
    portal_support_whatsapp character varying(20),
    show_ratings boolean DEFAULT true NOT NULL,
    show_reconnect_button boolean DEFAULT true NOT NULL,
    show_social_links boolean DEFAULT false NOT NULL,
    facebook_url character varying(500),
    whatsapp_group_url character varying(500),
    instagram_url character varying(500),
    show_announcement boolean DEFAULT false NOT NULL,
    announcement_type character varying(20) DEFAULT 'info'::character varying NOT NULL,
    announcement_text character varying(500),
    portal_language character varying(10) DEFAULT 'en'::character varying NOT NULL,
    plans_section_title character varying(200),
    featured_plan_ids character varying(200),
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    show_plan_speed boolean DEFAULT true NOT NULL
);


--
-- Name: portal_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.portal_settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: portal_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.portal_settings_id_seq OWNED BY public.portal_settings.id;


--
-- Name: provisioning_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provisioning_attempts (
    id integer NOT NULL,
    customer_id integer NOT NULL,
    router_id integer,
    mac_address character varying(50),
    source_table public.provisioningattemptsource NOT NULL,
    source_pk integer NOT NULL,
    external_reference character varying(255),
    entrypoint public.provisioningattemptentrypoint NOT NULL,
    provisioning_state public.provisioningstate DEFAULT 'scheduled'::public.provisioningstate NOT NULL,
    online_state public.provisioningonlinestate DEFAULT 'unknown'::public.provisioningonlinestate NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    last_error character varying(255),
    last_attempt_at timestamp without time zone,
    router_updated_at timestamp without time zone,
    last_online_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: provisioning_attempts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.provisioning_attempts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: provisioning_attempts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.provisioning_attempts_id_seq OWNED BY public.provisioning_attempts.id;


--
-- Name: provisioning_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provisioning_logs (
    id integer NOT NULL,
    customer_id integer NOT NULL,
    router_id integer,
    mac_address character varying(50),
    action character varying NOT NULL,
    status character varying NOT NULL,
    error character varying(255),
    details character varying(255),
    log_date timestamp without time zone,
    attempt_id integer
);


--
-- Name: provisioning_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.provisioning_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: provisioning_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.provisioning_logs_id_seq OWNED BY public.provisioning_logs.id;


--
-- Name: provisioning_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.provisioning_tokens (
    id integer NOT NULL,
    user_id integer NOT NULL,
    token character varying(64) NOT NULL,
    router_name character varying(255) NOT NULL,
    identity character varying(255) NOT NULL,
    wireguard_ip character varying(15) NOT NULL,
    ssid character varying(100) DEFAULT 'Bitwave WiFi'::character varying NOT NULL,
    router_admin_password character varying(255) DEFAULT 'admin'::character varying NOT NULL,
    wg_private_key text,
    wg_public_key text,
    server_wg_pubkey text,
    server_public_ip character varying(45) NOT NULL,
    payment_methods json DEFAULT '["mpesa", "voucher"]'::json NOT NULL,
    status public.provisioningtokenstatus DEFAULT 'pending'::public.provisioningtokenstatus NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    provisioned_at timestamp without time zone,
    router_id integer,
    vpn_type character varying(20) DEFAULT 'wireguard'::character varying NOT NULL,
    l2tp_username character varying,
    l2tp_password character varying,
    is_routerboard boolean DEFAULT false NOT NULL
);


--
-- Name: provisioning_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.provisioning_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: provisioning_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.provisioning_tokens_id_seq OWNED BY public.provisioning_tokens.id;


--
-- Name: radius_accounting; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radius_accounting (
    id bigint NOT NULL,
    acctsessionid character varying(64) NOT NULL,
    acctuniqueid character varying(32) NOT NULL,
    username character varying(64) NOT NULL,
    realm character varying(64),
    nasipaddress character varying(15) NOT NULL,
    nasportid character varying(32),
    nasporttype character varying(32),
    acctstarttime timestamp without time zone,
    acctupdatetime timestamp without time zone,
    acctstoptime timestamp without time zone,
    acctsessiontime integer,
    acctauthentic character varying(32),
    connectinfo_start character varying(128),
    connectinfo_stop character varying(128),
    acctinputoctets bigint,
    acctoutputoctets bigint,
    calledstationid character varying(50),
    callingstationid character varying(50),
    acctterminatecause character varying(32),
    servicetype character varying(32),
    framedprotocol character varying(32),
    framedipaddress character varying(15),
    framedipv6address character varying(45),
    framedipv6prefix character varying(45),
    framedinterfaceid character varying(44),
    delegatedipv6prefix character varying(45)
);


--
-- Name: radius_accounting_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radius_accounting_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radius_accounting_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radius_accounting_id_seq OWNED BY public.radius_accounting.id;


--
-- Name: radius_check; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radius_check (
    id integer NOT NULL,
    username character varying(64) NOT NULL,
    attribute character varying(64) NOT NULL,
    op character(2) DEFAULT ':='::bpchar NOT NULL,
    value character varying(253) NOT NULL,
    expiry timestamp without time zone,
    customer_id integer,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: radius_check_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radius_check_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radius_check_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radius_check_id_seq OWNED BY public.radius_check.id;


--
-- Name: radius_groupcheck; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radius_groupcheck (
    id integer NOT NULL,
    groupname character varying(64) NOT NULL,
    attribute character varying(64) NOT NULL,
    op character(2) DEFAULT ':='::bpchar NOT NULL,
    value character varying(253) NOT NULL
);


--
-- Name: radius_groupcheck_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radius_groupcheck_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radius_groupcheck_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radius_groupcheck_id_seq OWNED BY public.radius_groupcheck.id;


--
-- Name: radius_groupreply; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radius_groupreply (
    id integer NOT NULL,
    groupname character varying(64) NOT NULL,
    attribute character varying(64) NOT NULL,
    op character(2) DEFAULT ':='::bpchar NOT NULL,
    value character varying(253) NOT NULL
);


--
-- Name: radius_groupreply_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radius_groupreply_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radius_groupreply_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radius_groupreply_id_seq OWNED BY public.radius_groupreply.id;


--
-- Name: radius_nas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radius_nas (
    id integer NOT NULL,
    nasname character varying(128) NOT NULL,
    shortname character varying(32),
    type character varying(30) DEFAULT 'other'::character varying,
    ports integer,
    secret character varying(60) NOT NULL,
    server character varying(64),
    community character varying(50),
    description character varying(200),
    router_id integer,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: radius_nas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radius_nas_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radius_nas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radius_nas_id_seq OWNED BY public.radius_nas.id;


--
-- Name: radius_postauth; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radius_postauth (
    id bigint NOT NULL,
    username character varying(64) NOT NULL,
    pass character varying(64),
    reply character varying(32),
    authdate timestamp without time zone DEFAULT now() NOT NULL,
    nasipaddress character varying(15),
    calledstationid character varying(50),
    callingstationid character varying(50)
);


--
-- Name: radius_postauth_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radius_postauth_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radius_postauth_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radius_postauth_id_seq OWNED BY public.radius_postauth.id;


--
-- Name: radius_reply; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radius_reply (
    id integer NOT NULL,
    username character varying(64) NOT NULL,
    attribute character varying(64) NOT NULL,
    op character(2) DEFAULT ':='::bpchar NOT NULL,
    value character varying(253) NOT NULL,
    expiry timestamp without time zone,
    customer_id integer,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: radius_reply_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radius_reply_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radius_reply_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radius_reply_id_seq OWNED BY public.radius_reply.id;


--
-- Name: radius_usergroup; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radius_usergroup (
    id integer NOT NULL,
    username character varying(64) NOT NULL,
    groupname character varying(64) NOT NULL,
    priority integer DEFAULT 1 NOT NULL
);


--
-- Name: radius_usergroup_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radius_usergroup_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radius_usergroup_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radius_usergroup_id_seq OWNED BY public.radius_usergroup.id;


--
-- Name: reconnection_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reconnection_attempts (
    id integer NOT NULL,
    phone character varying NOT NULL,
    mac_address character varying NOT NULL,
    router_id integer NOT NULL,
    customer_id integer,
    success boolean DEFAULT false NOT NULL,
    failure_reason character varying(255),
    old_mac_address character varying,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: reconnection_attempts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.reconnection_attempts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: reconnection_attempts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.reconnection_attempts_id_seq OWNED BY public.reconnection_attempts.id;


--
-- Name: reseller_financials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reseller_financials (
    id integer NOT NULL,
    user_id integer NOT NULL,
    total_revenue double precision,
    total_customers integer,
    active_customers integer,
    last_payment_date timestamp without time zone,
    updated_at timestamp without time zone,
    balance_correction double precision DEFAULT 0.0 NOT NULL,
    balance_corrected_at timestamp without time zone,
    payout_frequency character varying(10) DEFAULT 'daily'::character varying NOT NULL,
    payout_interval_days integer
);


--
-- Name: reseller_financials_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.reseller_financials_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: reseller_financials_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.reseller_financials_id_seq OWNED BY public.reseller_financials.id;


--
-- Name: reseller_inbox_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reseller_inbox_messages (
    id integer NOT NULL,
    recipient_user_id integer NOT NULL,
    sender_user_id integer NOT NULL,
    subject character varying(200),
    body character varying(2000) NOT NULL,
    is_read boolean DEFAULT false NOT NULL,
    read_at timestamp without time zone,
    sent_sms boolean DEFAULT false NOT NULL,
    broadcast_id character varying(64),
    created_at timestamp without time zone
);


--
-- Name: reseller_inbox_messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.reseller_inbox_messages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: reseller_inbox_messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.reseller_inbox_messages_id_seq OWNED BY public.reseller_inbox_messages.id;


--
-- Name: reseller_payment_methods; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reseller_payment_methods (
    id integer NOT NULL,
    user_id integer NOT NULL,
    method_type public.resellerpaymentmethodtype NOT NULL,
    label character varying(100) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    bank_paybill_number character varying(20),
    bank_account_number character varying(50),
    mpesa_paybill_number character varying(20),
    mpesa_shortcode character varying(20),
    mpesa_passkey_encrypted character varying(500),
    mpesa_consumer_key_encrypted character varying(500),
    mpesa_consumer_secret_encrypted character varying(500),
    zenopay_api_key_encrypted character varying(500),
    zenopay_account_id character varying(100),
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    mtn_api_user character varying(64),
    mtn_api_key_encrypted character varying(500),
    mtn_subscription_key_encrypted character varying(500),
    mtn_target_environment character varying(50),
    mtn_base_url character varying(255),
    mtn_currency character varying(10),
    c2b_validation_url character varying(500),
    c2b_confirmation_url character varying(500),
    c2b_registered_at timestamp without time zone,
    mpesa_till_number character varying(20)
);


--
-- Name: reseller_payment_methods_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.reseller_payment_methods_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: reseller_payment_methods_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.reseller_payment_methods_id_seq OWNED BY public.reseller_payment_methods.id;


--
-- Name: reseller_payouts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reseller_payouts (
    id integer NOT NULL,
    reseller_id integer NOT NULL,
    amount double precision NOT NULL,
    payment_method character varying(50) NOT NULL,
    reference character varying(255),
    notes character varying(500),
    period_start timestamp without time zone,
    period_end timestamp without time zone,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: reseller_payouts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.reseller_payouts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: reseller_payouts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.reseller_payouts_id_seq OWNED BY public.reseller_payouts.id;


--
-- Name: reseller_transaction_charges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reseller_transaction_charges (
    id integer NOT NULL,
    reseller_id integer NOT NULL,
    amount double precision NOT NULL,
    description character varying(255) NOT NULL,
    reference character varying(255),
    created_by integer NOT NULL,
    created_at timestamp without time zone
);


--
-- Name: reseller_transaction_charges_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.reseller_transaction_charges_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: reseller_transaction_charges_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.reseller_transaction_charges_id_seq OWNED BY public.reseller_transaction_charges.id;


--
-- Name: router_availability_checks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.router_availability_checks (
    id integer NOT NULL,
    router_id integer NOT NULL,
    checked_at timestamp without time zone NOT NULL,
    is_online boolean NOT NULL,
    source character varying(50) NOT NULL
);


--
-- Name: router_availability_checks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.router_availability_checks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: router_availability_checks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.router_availability_checks_id_seq OWNED BY public.router_availability_checks.id;


--
-- Name: router_log_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.router_log_entries (
    id integer NOT NULL,
    router_id integer NOT NULL,
    topic character varying(50) NOT NULL,
    message character varying(1000) NOT NULL,
    username character varying(255),
    severity public.routerlogseverity NOT NULL,
    router_timestamp character varying(50),
    created_at timestamp without time zone
);


--
-- Name: router_log_entries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.router_log_entries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: router_log_entries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.router_log_entries_id_seq OWNED BY public.router_log_entries.id;


--
-- Name: router_usage_buckets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.router_usage_buckets (
    id integer NOT NULL,
    router_id integer NOT NULL,
    bucket_start timestamp without time zone NOT NULL,
    hotspot_upload_bytes bigint DEFAULT 0 NOT NULL,
    hotspot_download_bytes bigint DEFAULT 0 NOT NULL,
    pppoe_upload_bytes bigint DEFAULT 0 NOT NULL,
    pppoe_download_bytes bigint DEFAULT 0 NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: router_usage_buckets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.router_usage_buckets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: router_usage_buckets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.router_usage_buckets_id_seq OWNED BY public.router_usage_buckets.id;


--
-- Name: routers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.routers (
    id integer NOT NULL,
    user_id integer NOT NULL,
    name character varying NOT NULL,
    ip_address character varying NOT NULL,
    username character varying NOT NULL,
    password character varying NOT NULL,
    port integer NOT NULL,
    created_at timestamp without time zone,
    identity character varying,
    auth_method public.routerauthmethod DEFAULT 'DIRECT_API'::public.routerauthmethod NOT NULL,
    radius_secret character varying(255),
    radius_nas_identifier character varying(100),
    payment_methods json DEFAULT '["mpesa", "voucher"]'::json NOT NULL,
    pppoe_ports json,
    last_status boolean,
    last_checked_at timestamp without time zone,
    last_online_at timestamp without time zone,
    last_status_source character varying(50),
    availability_checks integer DEFAULT 0 NOT NULL,
    availability_successes integer DEFAULT 0 NOT NULL,
    emergency_active boolean DEFAULT false NOT NULL,
    emergency_message character varying(500),
    plain_ports json,
    payment_method_id integer,
    dual_ports json,
    hotspot_sharing_blocked boolean DEFAULT false NOT NULL,
    pull_channel_enabled boolean DEFAULT false NOT NULL,
    status_alerts_enabled boolean DEFAULT true NOT NULL,
    online_notified_at timestamp without time zone,
    offline_notified_at timestamp without time zone
);


--
-- Name: routers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.routers_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: routers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.routers_id_seq OWNED BY public.routers.id;


--
-- Name: shop_order_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.shop_order_items (
    id integer NOT NULL,
    order_id integer NOT NULL,
    product_id integer,
    product_name character varying(255) NOT NULL,
    product_price numeric(10,2) NOT NULL,
    quantity integer NOT NULL,
    subtotal numeric(10,2) NOT NULL
);


--
-- Name: shop_order_items_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.shop_order_items_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: shop_order_items_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.shop_order_items_id_seq OWNED BY public.shop_order_items.id;


--
-- Name: shop_order_tracking; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.shop_order_tracking (
    id integer NOT NULL,
    order_id integer NOT NULL,
    status_label character varying(100) NOT NULL,
    note character varying(500),
    updated_by_user_id integer,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: shop_order_tracking_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.shop_order_tracking_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: shop_order_tracking_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.shop_order_tracking_id_seq OWNED BY public.shop_order_tracking.id;


--
-- Name: shop_orders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.shop_orders (
    id integer NOT NULL,
    order_number character varying(20) NOT NULL,
    user_id integer NOT NULL,
    buyer_name character varying(255) NOT NULL,
    buyer_phone character varying(20) NOT NULL,
    buyer_email character varying(100),
    delivery_address character varying(500),
    total_amount numeric(10,2) NOT NULL,
    status public.shoporderstatus DEFAULT 'pending'::public.shoporderstatus NOT NULL,
    payment_status public.shoporderpaymentstatus DEFAULT 'unpaid'::public.shoporderpaymentstatus NOT NULL,
    mpesa_checkout_request_id character varying(255),
    mpesa_receipt_number character varying(255),
    notes character varying(500),
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: shop_orders_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.shop_orders_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: shop_orders_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.shop_orders_id_seq OWNED BY public.shop_orders.id;


--
-- Name: shop_products; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.shop_products (
    id integer NOT NULL,
    user_id integer NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(2000),
    price numeric(10,2) NOT NULL,
    stock_quantity integer DEFAULT 0 NOT NULL,
    image_url character varying(500),
    category character varying(100),
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: shop_products_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.shop_products_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: shop_products_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.shop_products_id_seq OWNED BY public.shop_products.id;


--
-- Name: sms_campaigns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sms_campaigns (
    id integer NOT NULL,
    user_id integer NOT NULL,
    body character varying(1000) NOT NULL,
    recipient_count integer NOT NULL,
    segments_per_message integer NOT NULL,
    total_credits integer NOT NULL,
    sent_count integer DEFAULT 0 NOT NULL,
    failed_count integer DEFAULT 0 NOT NULL,
    refunded_credits integer DEFAULT 0 NOT NULL,
    sender_id character varying(20),
    status public.smscampaignstatus NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: sms_campaigns_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sms_campaigns_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sms_campaigns_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sms_campaigns_id_seq OWNED BY public.sms_campaigns.id;


--
-- Name: sms_credit_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sms_credit_accounts (
    id integer NOT NULL,
    user_id integer NOT NULL,
    balance integer DEFAULT 0 NOT NULL,
    total_purchased integer DEFAULT 0 NOT NULL,
    total_spent integer DEFAULT 0 NOT NULL,
    updated_at timestamp without time zone,
    CONSTRAINT ck_sms_credit_balance_non_negative CHECK ((balance >= 0))
);


--
-- Name: sms_credit_accounts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sms_credit_accounts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sms_credit_accounts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sms_credit_accounts_id_seq OWNED BY public.sms_credit_accounts.id;


--
-- Name: sms_credit_orders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sms_credit_orders (
    id integer NOT NULL,
    user_id integer NOT NULL,
    quantity integer NOT NULL,
    unit_price numeric(6,2) NOT NULL,
    amount integer NOT NULL,
    phone_number character varying(20) NOT NULL,
    status public.smscreditorderstatus NOT NULL,
    mpesa_checkout_request_id character varying(128),
    mpesa_merchant_request_id character varying(128),
    payment_reference character varying(128),
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: sms_credit_orders_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sms_credit_orders_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sms_credit_orders_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sms_credit_orders_id_seq OWNED BY public.sms_credit_orders.id;


--
-- Name: sms_credit_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sms_credit_transactions (
    id integer NOT NULL,
    user_id integer NOT NULL,
    change integer NOT NULL,
    balance_after integer NOT NULL,
    kind public.smscredittxnkind NOT NULL,
    reference character varying(64),
    note character varying(255),
    created_at timestamp without time zone
);


--
-- Name: sms_credit_transactions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sms_credit_transactions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sms_credit_transactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sms_credit_transactions_id_seq OWNED BY public.sms_credit_transactions.id;


--
-- Name: sms_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sms_messages (
    id integer NOT NULL,
    campaign_id integer,
    user_id integer NOT NULL,
    customer_id integer,
    recipient_phone character varying(20) NOT NULL,
    body character varying(1000) NOT NULL,
    segments integer NOT NULL,
    credits_charged integer NOT NULL,
    kind public.smsmessagekind NOT NULL,
    provider character varying(50),
    provider_message_id character varying(128),
    status public.smsmessagestatus NOT NULL,
    error character varying(255),
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    category character varying(40)
);


--
-- Name: sms_messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sms_messages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sms_messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sms_messages_id_seq OWNED BY public.sms_messages.id;


--
-- Name: subscription_invoices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.subscription_invoices (
    id integer NOT NULL,
    user_id integer NOT NULL,
    period_start timestamp without time zone NOT NULL,
    period_end timestamp without time zone NOT NULL,
    hotspot_revenue double precision DEFAULT 0 NOT NULL,
    hotspot_charge double precision DEFAULT 0 NOT NULL,
    pppoe_user_count integer DEFAULT 0 NOT NULL,
    pppoe_charge double precision DEFAULT 0 NOT NULL,
    gross_charge double precision DEFAULT 0 NOT NULL,
    final_charge double precision DEFAULT 0 NOT NULL,
    status public.invoicestatus DEFAULT 'pending'::public.invoicestatus NOT NULL,
    due_date timestamp without time zone NOT NULL,
    paid_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: subscription_invoices_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.subscription_invoices_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: subscription_invoices_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.subscription_invoices_id_seq OWNED BY public.subscription_invoices.id;


--
-- Name: subscription_payments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.subscription_payments (
    id integer NOT NULL,
    invoice_id integer,
    user_id integer NOT NULL,
    amount double precision NOT NULL,
    payment_method character varying(50) DEFAULT 'mpesa'::character varying NOT NULL,
    payment_reference character varying(255),
    mpesa_checkout_request_id character varying(255),
    phone_number character varying(20),
    status public.subscriptionpaymentstatus DEFAULT 'pending'::public.subscriptionpaymentstatus NOT NULL,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: subscription_payments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.subscription_payments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: subscription_payments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.subscription_payments_id_seq OWNED BY public.subscription_payments.id;


--
-- Name: subscription_share_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.subscription_share_codes (
    id integer NOT NULL,
    code character varying(16) NOT NULL,
    router_id integer NOT NULL,
    owner_customer_id integer NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    redeemed_customer_id integer,
    redeemed_pairing_id integer,
    redeemed_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: subscription_share_codes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.subscription_share_codes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: subscription_share_codes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.subscription_share_codes_id_seq OWNED BY public.subscription_share_codes.id;


--
-- Name: subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.subscriptions (
    id integer NOT NULL,
    user_id integer NOT NULL,
    is_active boolean,
    paid_on timestamp without time zone,
    expires_on timestamp without time zone,
    plan_type character varying,
    cost double precision,
    status public.subscriptionstatus DEFAULT 'trial'::public.subscriptionstatus,
    current_period_start timestamp without time zone,
    current_period_end timestamp without time zone,
    trial_ends_at timestamp without time zone,
    updated_at timestamp without time zone DEFAULT now(),
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: subscriptions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.subscriptions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: subscriptions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.subscriptions_id_seq OWNED BY public.subscriptions.id;


--
-- Name: unmatched_c2b_payments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.unmatched_c2b_payments (
    id integer NOT NULL,
    c2b_transaction_id integer NOT NULL,
    reason public.unmatchedc2breason NOT NULL,
    assigned_reseller_id integer,
    resolved_at timestamp without time zone,
    resolved_by_user_id integer,
    resolution_customer_id integer,
    notes character varying(500)
);


--
-- Name: unmatched_c2b_payments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.unmatched_c2b_payments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: unmatched_c2b_payments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.unmatched_c2b_payments_id_seq OWNED BY public.unmatched_c2b_payments.id;


--
-- Name: usage_cap_watch_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_cap_watch_state (
    id integer NOT NULL,
    customer_id integer NOT NULL,
    router_id integer NOT NULL,
    queue_key character varying(100),
    next_poll_at timestamp without time zone DEFAULT now() NOT NULL,
    last_polled_at timestamp without time zone,
    poll_interval_seconds integer DEFAULT 300 NOT NULL,
    poll_tier character varying(32) DEFAULT 'normal'::character varying NOT NULL,
    consecutive_errors integer DEFAULT 0 NOT NULL,
    backoff_until timestamp without time zone,
    locked_at timestamp without time zone,
    locked_by character varying(64),
    last_error character varying(500),
    last_enforcement_attempt_at timestamp without time zone,
    last_enforcement_error character varying(500),
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: usage_cap_watch_state_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.usage_cap_watch_state_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: usage_cap_watch_state_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.usage_cap_watch_state_id_seq OWNED BY public.usage_cap_watch_state.id;


--
-- Name: user_bandwidth_usage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_bandwidth_usage (
    id integer NOT NULL,
    mac_address character varying(50),
    customer_id integer,
    queue_name character varying(100),
    target_ip character varying(50),
    upload_bytes bigint,
    download_bytes bigint,
    max_limit character varying(50),
    last_updated timestamp without time zone,
    last_upload_bytes bigint DEFAULT 0 NOT NULL,
    last_download_bytes bigint DEFAULT 0 NOT NULL
);


--
-- Name: user_bandwidth_usage_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_bandwidth_usage_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_bandwidth_usage_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_bandwidth_usage_id_seq OWNED BY public.user_bandwidth_usage.id;


--
-- Name: user_payment_methods; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_payment_methods (
    id integer NOT NULL,
    user_id integer NOT NULL,
    method_type public.paymentmethodtype NOT NULL,
    label character varying(100),
    is_active boolean DEFAULT false NOT NULL,
    bank_paybill_number character varying(20),
    bank_account_number character varying(50),
    paybill_number character varying(20),
    mpesa_shortcode character varying(20),
    mpesa_passkey character varying(255),
    consumer_key character varying(255),
    consumer_secret character varying(255),
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: user_payment_methods_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_payment_methods_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_payment_methods_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_payment_methods_id_seq OWNED BY public.user_payment_methods.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id integer NOT NULL,
    user_code bigint NOT NULL,
    email character varying NOT NULL,
    password_hash character varying NOT NULL,
    role public.userrole NOT NULL,
    organization_name character varying NOT NULL,
    created_by integer,
    created_at timestamp without time zone,
    business_name character varying(255),
    mpesa_shortcode character varying(20),
    support_phone character varying(20),
    last_login_at timestamp without time zone,
    subscription_status public.subscriptionstatus DEFAULT 'trial'::public.subscriptionstatus NOT NULL,
    subscription_expires_at timestamp without time zone
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: vouchers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vouchers (
    id integer NOT NULL,
    code character varying(9) NOT NULL,
    plan_id integer NOT NULL,
    router_id integer,
    user_id integer NOT NULL,
    status public.voucherstatus DEFAULT 'available'::public.voucherstatus NOT NULL,
    batch_id character varying(36),
    redeemed_by integer,
    redeemed_at timestamp without time zone,
    expires_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now(),
    voucher_type public.vouchertype DEFAULT 'sale'::public.vouchertype NOT NULL
);


--
-- Name: vouchers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vouchers_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vouchers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vouchers_id_seq OWNED BY public.vouchers.id;


--
-- Name: work_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.work_items (
    id integer NOT NULL,
    code character varying(32),
    title character varying(300) NOT NULL,
    detail character varying(4000),
    source character varying(32) DEFAULT 'manual'::character varying NOT NULL,
    status character varying(32) DEFAULT 'queued'::character varying NOT NULL,
    owner character varying(64),
    priority integer DEFAULT 0 NOT NULL,
    branch character varying(200),
    pr_url character varying(300),
    blocked_reason character varying(500),
    session_url character varying(500),
    session_surface character varying(32),
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    completed_at timestamp without time zone
);


--
-- Name: work_items_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.work_items_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: work_items_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.work_items_id_seq OWNED BY public.work_items.id;


--
-- Name: zenopay_transactions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.zenopay_transactions (
    id integer NOT NULL,
    order_id character varying(255) NOT NULL,
    reseller_id integer NOT NULL,
    customer_id integer,
    amount numeric(10,2) NOT NULL,
    status public.zenopaytransactionstatus NOT NULL,
    reference character varying(255),
    channel character varying(50),
    buyer_phone character varying(20) NOT NULL,
    buyer_name character varying(100),
    buyer_email character varying(100),
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: zenopay_transactions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.zenopay_transactions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: zenopay_transactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.zenopay_transactions_id_seq OWNED BY public.zenopay_transactions.id;


--
-- Name: access_credentials id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_credentials ALTER COLUMN id SET DEFAULT nextval('public.access_credentials_id_seq'::regclass);


--
-- Name: ad_clicks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ad_clicks ALTER COLUMN id SET DEFAULT nextval('public.ad_clicks_id_seq'::regclass);


--
-- Name: ad_impressions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ad_impressions ALTER COLUMN id SET DEFAULT nextval('public.ad_impressions_id_seq'::regclass);


--
-- Name: ads id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ads ALTER COLUMN id SET DEFAULT nextval('public.ads_id_seq'::regclass);


--
-- Name: advertisers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advertisers ALTER COLUMN id SET DEFAULT nextval('public.advertisers_id_seq'::regclass);


--
-- Name: agent_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_runs ALTER COLUMN id SET DEFAULT nextval('public.agent_runs_id_seq'::regclass);


--
-- Name: agent_schedules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_schedules ALTER COLUMN id SET DEFAULT nextval('public.agent_schedules_id_seq'::regclass);


--
-- Name: approvals id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approvals ALTER COLUMN id SET DEFAULT nextval('public.approvals_id_seq'::regclass);


--
-- Name: b2b_transactions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.b2b_transactions ALTER COLUMN id SET DEFAULT nextval('public.b2b_transactions_id_seq'::regclass);


--
-- Name: bandwidth_snapshots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bandwidth_snapshots ALTER COLUMN id SET DEFAULT nextval('public.bandwidth_snapshots_id_seq'::regclass);


--
-- Name: c2b_transactions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.c2b_transactions ALTER COLUMN id SET DEFAULT nextval('public.c2b_transactions_id_seq'::regclass);


--
-- Name: customer_payments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_payments ALTER COLUMN id SET DEFAULT nextval('public.customer_payments_id_seq'::regclass);


--
-- Name: customer_ratings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_ratings ALTER COLUMN id SET DEFAULT nextval('public.customer_ratings_id_seq'::regclass);


--
-- Name: customer_usage_periods id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_usage_periods ALTER COLUMN id SET DEFAULT nextval('public.customer_usage_periods_id_seq'::regclass);


--
-- Name: customers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customers ALTER COLUMN id SET DEFAULT nextval('public.customers_id_seq'::regclass);


--
-- Name: device_pairings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_pairings ALTER COLUMN id SET DEFAULT nextval('public.device_pairings_id_seq'::regclass);


--
-- Name: feedback_comments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_comments ALTER COLUMN id SET DEFAULT nextval('public.feedback_comments_id_seq'::regclass);


--
-- Name: feedback_posts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_posts ALTER COLUMN id SET DEFAULT nextval('public.feedback_posts_id_seq'::regclass);


--
-- Name: feedback_votes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_votes ALTER COLUMN id SET DEFAULT nextval('public.feedback_votes_id_seq'::regclass);


--
-- Name: growth_targets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.growth_targets ALTER COLUMN id SET DEFAULT nextval('public.growth_targets_id_seq'::regclass);


--
-- Name: lead_activities id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_activities ALTER COLUMN id SET DEFAULT nextval('public.lead_activities_id_seq'::regclass);


--
-- Name: lead_follow_ups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_follow_ups ALTER COLUMN id SET DEFAULT nextval('public.lead_follow_ups_id_seq'::regclass);


--
-- Name: lead_sources id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_sources ALTER COLUMN id SET DEFAULT nextval('public.lead_sources_id_seq'::regclass);


--
-- Name: leads id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.leads ALTER COLUMN id SET DEFAULT nextval('public.leads_id_seq'::regclass);


--
-- Name: message_templates id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_templates ALTER COLUMN id SET DEFAULT nextval('public.message_templates_id_seq'::regclass);


--
-- Name: messaging_settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messaging_settings ALTER COLUMN id SET DEFAULT nextval('public.messaging_settings_id_seq'::regclass);


--
-- Name: mpesa_transactions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mpesa_transactions ALTER COLUMN id SET DEFAULT nextval('public.mpesa_transactions_id_seq'::regclass);


--
-- Name: mtn_momo_transactions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mtn_momo_transactions ALTER COLUMN id SET DEFAULT nextval('public.mtn_momo_transactions_id_seq'::regclass);


--
-- Name: password_reset_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens ALTER COLUMN id SET DEFAULT nextval('public.password_reset_tokens_id_seq'::regclass);


--
-- Name: payments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payments ALTER COLUMN id SET DEFAULT nextval('public.payments_id_seq'::regclass);


--
-- Name: plans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plans ALTER COLUMN id SET DEFAULT nextval('public.plans_id_seq'::regclass);


--
-- Name: portal_settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.portal_settings ALTER COLUMN id SET DEFAULT nextval('public.portal_settings_id_seq'::regclass);


--
-- Name: provisioning_attempts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_attempts ALTER COLUMN id SET DEFAULT nextval('public.provisioning_attempts_id_seq'::regclass);


--
-- Name: provisioning_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_logs ALTER COLUMN id SET DEFAULT nextval('public.provisioning_logs_id_seq'::regclass);


--
-- Name: provisioning_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_tokens ALTER COLUMN id SET DEFAULT nextval('public.provisioning_tokens_id_seq'::regclass);


--
-- Name: radius_accounting id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_accounting ALTER COLUMN id SET DEFAULT nextval('public.radius_accounting_id_seq'::regclass);


--
-- Name: radius_check id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_check ALTER COLUMN id SET DEFAULT nextval('public.radius_check_id_seq'::regclass);


--
-- Name: radius_groupcheck id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_groupcheck ALTER COLUMN id SET DEFAULT nextval('public.radius_groupcheck_id_seq'::regclass);


--
-- Name: radius_groupreply id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_groupreply ALTER COLUMN id SET DEFAULT nextval('public.radius_groupreply_id_seq'::regclass);


--
-- Name: radius_nas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_nas ALTER COLUMN id SET DEFAULT nextval('public.radius_nas_id_seq'::regclass);


--
-- Name: radius_postauth id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_postauth ALTER COLUMN id SET DEFAULT nextval('public.radius_postauth_id_seq'::regclass);


--
-- Name: radius_reply id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_reply ALTER COLUMN id SET DEFAULT nextval('public.radius_reply_id_seq'::regclass);


--
-- Name: radius_usergroup id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_usergroup ALTER COLUMN id SET DEFAULT nextval('public.radius_usergroup_id_seq'::regclass);


--
-- Name: reconnection_attempts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reconnection_attempts ALTER COLUMN id SET DEFAULT nextval('public.reconnection_attempts_id_seq'::regclass);


--
-- Name: reseller_financials id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_financials ALTER COLUMN id SET DEFAULT nextval('public.reseller_financials_id_seq'::regclass);


--
-- Name: reseller_inbox_messages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_inbox_messages ALTER COLUMN id SET DEFAULT nextval('public.reseller_inbox_messages_id_seq'::regclass);


--
-- Name: reseller_payment_methods id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_payment_methods ALTER COLUMN id SET DEFAULT nextval('public.reseller_payment_methods_id_seq'::regclass);


--
-- Name: reseller_payouts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_payouts ALTER COLUMN id SET DEFAULT nextval('public.reseller_payouts_id_seq'::regclass);


--
-- Name: reseller_transaction_charges id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_transaction_charges ALTER COLUMN id SET DEFAULT nextval('public.reseller_transaction_charges_id_seq'::regclass);


--
-- Name: router_availability_checks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.router_availability_checks ALTER COLUMN id SET DEFAULT nextval('public.router_availability_checks_id_seq'::regclass);


--
-- Name: router_log_entries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.router_log_entries ALTER COLUMN id SET DEFAULT nextval('public.router_log_entries_id_seq'::regclass);


--
-- Name: router_usage_buckets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.router_usage_buckets ALTER COLUMN id SET DEFAULT nextval('public.router_usage_buckets_id_seq'::regclass);


--
-- Name: routers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.routers ALTER COLUMN id SET DEFAULT nextval('public.routers_id_seq'::regclass);


--
-- Name: shop_order_items id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_order_items ALTER COLUMN id SET DEFAULT nextval('public.shop_order_items_id_seq'::regclass);


--
-- Name: shop_order_tracking id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_order_tracking ALTER COLUMN id SET DEFAULT nextval('public.shop_order_tracking_id_seq'::regclass);


--
-- Name: shop_orders id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_orders ALTER COLUMN id SET DEFAULT nextval('public.shop_orders_id_seq'::regclass);


--
-- Name: shop_products id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_products ALTER COLUMN id SET DEFAULT nextval('public.shop_products_id_seq'::regclass);


--
-- Name: sms_campaigns id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_campaigns ALTER COLUMN id SET DEFAULT nextval('public.sms_campaigns_id_seq'::regclass);


--
-- Name: sms_credit_accounts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_credit_accounts ALTER COLUMN id SET DEFAULT nextval('public.sms_credit_accounts_id_seq'::regclass);


--
-- Name: sms_credit_orders id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_credit_orders ALTER COLUMN id SET DEFAULT nextval('public.sms_credit_orders_id_seq'::regclass);


--
-- Name: sms_credit_transactions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_credit_transactions ALTER COLUMN id SET DEFAULT nextval('public.sms_credit_transactions_id_seq'::regclass);


--
-- Name: sms_messages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_messages ALTER COLUMN id SET DEFAULT nextval('public.sms_messages_id_seq'::regclass);


--
-- Name: subscription_invoices id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_invoices ALTER COLUMN id SET DEFAULT nextval('public.subscription_invoices_id_seq'::regclass);


--
-- Name: subscription_payments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_payments ALTER COLUMN id SET DEFAULT nextval('public.subscription_payments_id_seq'::regclass);


--
-- Name: subscription_share_codes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_share_codes ALTER COLUMN id SET DEFAULT nextval('public.subscription_share_codes_id_seq'::regclass);


--
-- Name: subscriptions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscriptions ALTER COLUMN id SET DEFAULT nextval('public.subscriptions_id_seq'::regclass);


--
-- Name: unmatched_c2b_payments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unmatched_c2b_payments ALTER COLUMN id SET DEFAULT nextval('public.unmatched_c2b_payments_id_seq'::regclass);


--
-- Name: usage_cap_watch_state id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_cap_watch_state ALTER COLUMN id SET DEFAULT nextval('public.usage_cap_watch_state_id_seq'::regclass);


--
-- Name: user_bandwidth_usage id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_bandwidth_usage ALTER COLUMN id SET DEFAULT nextval('public.user_bandwidth_usage_id_seq'::regclass);


--
-- Name: user_payment_methods id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_payment_methods ALTER COLUMN id SET DEFAULT nextval('public.user_payment_methods_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: vouchers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vouchers ALTER COLUMN id SET DEFAULT nextval('public.vouchers_id_seq'::regclass);


--
-- Name: work_items id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.work_items ALTER COLUMN id SET DEFAULT nextval('public.work_items_id_seq'::regclass);


--
-- Name: zenopay_transactions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zenopay_transactions ALTER COLUMN id SET DEFAULT nextval('public.zenopay_transactions_id_seq'::regclass);


--
-- Name: access_credentials access_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_credentials
    ADD CONSTRAINT access_credentials_pkey PRIMARY KEY (id);


--
-- Name: ad_clicks ad_clicks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ad_clicks
    ADD CONSTRAINT ad_clicks_pkey PRIMARY KEY (id);


--
-- Name: ad_impressions ad_impressions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ad_impressions
    ADD CONSTRAINT ad_impressions_pkey PRIMARY KEY (id);


--
-- Name: ads ads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ads
    ADD CONSTRAINT ads_pkey PRIMARY KEY (id);


--
-- Name: advertisers advertisers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.advertisers
    ADD CONSTRAINT advertisers_pkey PRIMARY KEY (id);


--
-- Name: agent_runs agent_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_runs
    ADD CONSTRAINT agent_runs_pkey PRIMARY KEY (id);


--
-- Name: agent_schedules agent_schedules_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_schedules
    ADD CONSTRAINT agent_schedules_name_key UNIQUE (name);


--
-- Name: agent_schedules agent_schedules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_schedules
    ADD CONSTRAINT agent_schedules_pkey PRIMARY KEY (id);


--
-- Name: app_settings app_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_settings
    ADD CONSTRAINT app_settings_pkey PRIMARY KEY (key);


--
-- Name: approvals approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_pkey PRIMARY KEY (id);


--
-- Name: b2b_transactions b2b_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.b2b_transactions
    ADD CONSTRAINT b2b_transactions_pkey PRIMARY KEY (id);


--
-- Name: bandwidth_snapshots bandwidth_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bandwidth_snapshots
    ADD CONSTRAINT bandwidth_snapshots_pkey PRIMARY KEY (id);


--
-- Name: c2b_transactions c2b_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.c2b_transactions
    ADD CONSTRAINT c2b_transactions_pkey PRIMARY KEY (id);


--
-- Name: customer_payments customer_payments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_payments
    ADD CONSTRAINT customer_payments_pkey PRIMARY KEY (id);


--
-- Name: customer_ratings customer_ratings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_ratings
    ADD CONSTRAINT customer_ratings_pkey PRIMARY KEY (id);


--
-- Name: customer_usage_periods customer_usage_periods_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_usage_periods
    ADD CONSTRAINT customer_usage_periods_pkey PRIMARY KEY (id);


--
-- Name: customers customers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_pkey PRIMARY KEY (id);


--
-- Name: device_pairings device_pairings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_pairings
    ADD CONSTRAINT device_pairings_pkey PRIMARY KEY (id);


--
-- Name: feedback_comments feedback_comments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_comments
    ADD CONSTRAINT feedback_comments_pkey PRIMARY KEY (id);


--
-- Name: feedback_posts feedback_posts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_posts
    ADD CONSTRAINT feedback_posts_pkey PRIMARY KEY (id);


--
-- Name: feedback_votes feedback_votes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_votes
    ADD CONSTRAINT feedback_votes_pkey PRIMARY KEY (id);


--
-- Name: growth_targets growth_targets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.growth_targets
    ADD CONSTRAINT growth_targets_pkey PRIMARY KEY (id);


--
-- Name: growth_targets growth_targets_target_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.growth_targets
    ADD CONSTRAINT growth_targets_target_id_key UNIQUE (target_id);


--
-- Name: lead_activities lead_activities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_activities
    ADD CONSTRAINT lead_activities_pkey PRIMARY KEY (id);


--
-- Name: lead_follow_ups lead_follow_ups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_follow_ups
    ADD CONSTRAINT lead_follow_ups_pkey PRIMARY KEY (id);


--
-- Name: lead_sources lead_sources_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_sources
    ADD CONSTRAINT lead_sources_name_key UNIQUE (name);


--
-- Name: lead_sources lead_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_sources
    ADD CONSTRAINT lead_sources_pkey PRIMARY KEY (id);


--
-- Name: leads leads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.leads
    ADD CONSTRAINT leads_pkey PRIMARY KEY (id);


--
-- Name: message_templates message_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_templates
    ADD CONSTRAINT message_templates_pkey PRIMARY KEY (id);


--
-- Name: messaging_settings messaging_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messaging_settings
    ADD CONSTRAINT messaging_settings_pkey PRIMARY KEY (id);


--
-- Name: mpesa_transactions mpesa_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mpesa_transactions
    ADD CONSTRAINT mpesa_transactions_pkey PRIMARY KEY (id);


--
-- Name: mtn_momo_transactions mtn_momo_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mtn_momo_transactions
    ADD CONSTRAINT mtn_momo_transactions_pkey PRIMARY KEY (id);


--
-- Name: mtn_momo_transactions mtn_momo_transactions_reference_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mtn_momo_transactions
    ADD CONSTRAINT mtn_momo_transactions_reference_id_key UNIQUE (reference_id);


--
-- Name: password_reset_tokens password_reset_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id);


--
-- Name: password_reset_tokens password_reset_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_token_hash_key UNIQUE (token_hash);


--
-- Name: payments payments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_pkey PRIMARY KEY (id);


--
-- Name: plans plans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plans
    ADD CONSTRAINT plans_pkey PRIMARY KEY (id);


--
-- Name: portal_settings portal_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.portal_settings
    ADD CONSTRAINT portal_settings_pkey PRIMARY KEY (id);


--
-- Name: portal_settings portal_settings_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.portal_settings
    ADD CONSTRAINT portal_settings_user_id_key UNIQUE (user_id);


--
-- Name: provisioning_attempts provisioning_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_attempts
    ADD CONSTRAINT provisioning_attempts_pkey PRIMARY KEY (id);


--
-- Name: provisioning_logs provisioning_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_logs
    ADD CONSTRAINT provisioning_logs_pkey PRIMARY KEY (id);


--
-- Name: provisioning_tokens provisioning_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_tokens
    ADD CONSTRAINT provisioning_tokens_pkey PRIMARY KEY (id);


--
-- Name: provisioning_tokens provisioning_tokens_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_tokens
    ADD CONSTRAINT provisioning_tokens_token_key UNIQUE (token);


--
-- Name: radius_accounting radius_accounting_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_accounting
    ADD CONSTRAINT radius_accounting_pkey PRIMARY KEY (id);


--
-- Name: radius_check radius_check_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_check
    ADD CONSTRAINT radius_check_pkey PRIMARY KEY (id);


--
-- Name: radius_groupcheck radius_groupcheck_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_groupcheck
    ADD CONSTRAINT radius_groupcheck_pkey PRIMARY KEY (id);


--
-- Name: radius_groupreply radius_groupreply_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_groupreply
    ADD CONSTRAINT radius_groupreply_pkey PRIMARY KEY (id);


--
-- Name: radius_nas radius_nas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_nas
    ADD CONSTRAINT radius_nas_pkey PRIMARY KEY (id);


--
-- Name: radius_postauth radius_postauth_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_postauth
    ADD CONSTRAINT radius_postauth_pkey PRIMARY KEY (id);


--
-- Name: radius_reply radius_reply_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_reply
    ADD CONSTRAINT radius_reply_pkey PRIMARY KEY (id);


--
-- Name: radius_usergroup radius_usergroup_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_usergroup
    ADD CONSTRAINT radius_usergroup_pkey PRIMARY KEY (id);


--
-- Name: reconnection_attempts reconnection_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reconnection_attempts
    ADD CONSTRAINT reconnection_attempts_pkey PRIMARY KEY (id);


--
-- Name: reseller_financials reseller_financials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_financials
    ADD CONSTRAINT reseller_financials_pkey PRIMARY KEY (id);


--
-- Name: reseller_financials reseller_financials_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_financials
    ADD CONSTRAINT reseller_financials_user_id_key UNIQUE (user_id);


--
-- Name: reseller_inbox_messages reseller_inbox_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_inbox_messages
    ADD CONSTRAINT reseller_inbox_messages_pkey PRIMARY KEY (id);


--
-- Name: reseller_payment_methods reseller_payment_methods_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_payment_methods
    ADD CONSTRAINT reseller_payment_methods_pkey PRIMARY KEY (id);


--
-- Name: reseller_payouts reseller_payouts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_payouts
    ADD CONSTRAINT reseller_payouts_pkey PRIMARY KEY (id);


--
-- Name: reseller_transaction_charges reseller_transaction_charges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_transaction_charges
    ADD CONSTRAINT reseller_transaction_charges_pkey PRIMARY KEY (id);


--
-- Name: router_availability_checks router_availability_checks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.router_availability_checks
    ADD CONSTRAINT router_availability_checks_pkey PRIMARY KEY (id);


--
-- Name: router_log_entries router_log_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.router_log_entries
    ADD CONSTRAINT router_log_entries_pkey PRIMARY KEY (id);


--
-- Name: router_usage_buckets router_usage_buckets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.router_usage_buckets
    ADD CONSTRAINT router_usage_buckets_pkey PRIMARY KEY (id);


--
-- Name: routers routers_identity_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.routers
    ADD CONSTRAINT routers_identity_key UNIQUE (identity);


--
-- Name: routers routers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.routers
    ADD CONSTRAINT routers_pkey PRIMARY KEY (id);


--
-- Name: shop_order_items shop_order_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_order_items
    ADD CONSTRAINT shop_order_items_pkey PRIMARY KEY (id);


--
-- Name: shop_order_tracking shop_order_tracking_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_order_tracking
    ADD CONSTRAINT shop_order_tracking_pkey PRIMARY KEY (id);


--
-- Name: shop_orders shop_orders_mpesa_checkout_request_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_orders
    ADD CONSTRAINT shop_orders_mpesa_checkout_request_id_key UNIQUE (mpesa_checkout_request_id);


--
-- Name: shop_orders shop_orders_order_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_orders
    ADD CONSTRAINT shop_orders_order_number_key UNIQUE (order_number);


--
-- Name: shop_orders shop_orders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_orders
    ADD CONSTRAINT shop_orders_pkey PRIMARY KEY (id);


--
-- Name: shop_products shop_products_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_products
    ADD CONSTRAINT shop_products_pkey PRIMARY KEY (id);


--
-- Name: sms_campaigns sms_campaigns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_campaigns
    ADD CONSTRAINT sms_campaigns_pkey PRIMARY KEY (id);


--
-- Name: sms_credit_accounts sms_credit_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_credit_accounts
    ADD CONSTRAINT sms_credit_accounts_pkey PRIMARY KEY (id);


--
-- Name: sms_credit_accounts sms_credit_accounts_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_credit_accounts
    ADD CONSTRAINT sms_credit_accounts_user_id_key UNIQUE (user_id);


--
-- Name: sms_credit_orders sms_credit_orders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_credit_orders
    ADD CONSTRAINT sms_credit_orders_pkey PRIMARY KEY (id);


--
-- Name: sms_credit_transactions sms_credit_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_credit_transactions
    ADD CONSTRAINT sms_credit_transactions_pkey PRIMARY KEY (id);


--
-- Name: sms_messages sms_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_messages
    ADD CONSTRAINT sms_messages_pkey PRIMARY KEY (id);


--
-- Name: subscription_invoices subscription_invoices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_invoices
    ADD CONSTRAINT subscription_invoices_pkey PRIMARY KEY (id);


--
-- Name: subscription_payments subscription_payments_mpesa_checkout_request_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_payments
    ADD CONSTRAINT subscription_payments_mpesa_checkout_request_id_key UNIQUE (mpesa_checkout_request_id);


--
-- Name: subscription_payments subscription_payments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_payments
    ADD CONSTRAINT subscription_payments_pkey PRIMARY KEY (id);


--
-- Name: subscription_share_codes subscription_share_codes_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_share_codes
    ADD CONSTRAINT subscription_share_codes_code_key UNIQUE (code);


--
-- Name: subscription_share_codes subscription_share_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_share_codes
    ADD CONSTRAINT subscription_share_codes_pkey PRIMARY KEY (id);


--
-- Name: subscriptions subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_pkey PRIMARY KEY (id);


--
-- Name: unmatched_c2b_payments unmatched_c2b_payments_c2b_transaction_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unmatched_c2b_payments
    ADD CONSTRAINT unmatched_c2b_payments_c2b_transaction_id_key UNIQUE (c2b_transaction_id);


--
-- Name: unmatched_c2b_payments unmatched_c2b_payments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unmatched_c2b_payments
    ADD CONSTRAINT unmatched_c2b_payments_pkey PRIMARY KEY (id);


--
-- Name: access_credentials uq_access_cred_router_username; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_credentials
    ADD CONSTRAINT uq_access_cred_router_username UNIQUE (router_id, username);


--
-- Name: customers uq_customer_mac_per_reseller; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customers
    ADD CONSTRAINT uq_customer_mac_per_reseller UNIQUE (mac_address, user_id);


--
-- Name: customer_usage_periods uq_customer_period_start; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_usage_periods
    ADD CONSTRAINT uq_customer_period_start UNIQUE (customer_id, period_start);


--
-- Name: device_pairings uq_device_mac_per_router; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_pairings
    ADD CONSTRAINT uq_device_mac_per_router UNIQUE (device_mac, router_id);


--
-- Name: feedback_votes uq_feedback_votes_post_user; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_votes
    ADD CONSTRAINT uq_feedback_votes_post_user UNIQUE (post_id, user_id);


--
-- Name: provisioning_attempts uq_provisioning_attempt_source; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_attempts
    ADD CONSTRAINT uq_provisioning_attempt_source UNIQUE (source_table, source_pk);


--
-- Name: router_usage_buckets uq_router_usage_bucket; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.router_usage_buckets
    ADD CONSTRAINT uq_router_usage_bucket UNIQUE (router_id, bucket_start);


--
-- Name: subscription_invoices uq_subscription_invoice_user_period; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_invoices
    ADD CONSTRAINT uq_subscription_invoice_user_period UNIQUE (user_id, period_start);


--
-- Name: subscriptions uq_subscriptions_user_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT uq_subscriptions_user_id UNIQUE (user_id);


--
-- Name: usage_cap_watch_state uq_usage_cap_watch_customer; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_cap_watch_state
    ADD CONSTRAINT uq_usage_cap_watch_customer UNIQUE (customer_id);


--
-- Name: usage_cap_watch_state usage_cap_watch_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_cap_watch_state
    ADD CONSTRAINT usage_cap_watch_state_pkey PRIMARY KEY (id);


--
-- Name: user_bandwidth_usage user_bandwidth_usage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_bandwidth_usage
    ADD CONSTRAINT user_bandwidth_usage_pkey PRIMARY KEY (id);


--
-- Name: user_payment_methods user_payment_methods_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_payment_methods
    ADD CONSTRAINT user_payment_methods_pkey PRIMARY KEY (id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_user_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_user_code_key UNIQUE (user_code);


--
-- Name: vouchers vouchers_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vouchers
    ADD CONSTRAINT vouchers_code_key UNIQUE (code);


--
-- Name: vouchers vouchers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vouchers
    ADD CONSTRAINT vouchers_pkey PRIMARY KEY (id);


--
-- Name: work_items work_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.work_items
    ADD CONSTRAINT work_items_pkey PRIMARY KEY (id);


--
-- Name: zenopay_transactions zenopay_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zenopay_transactions
    ADD CONSTRAINT zenopay_transactions_pkey PRIMARY KEY (id);


--
-- Name: idx_access_cred_bound_mac; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_access_cred_bound_mac ON public.access_credentials USING btree (bound_mac_address);


--
-- Name: idx_access_cred_router; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_access_cred_router ON public.access_credentials USING btree (router_id);


--
-- Name: idx_access_cred_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_access_cred_user ON public.access_credentials USING btree (user_id);


--
-- Name: idx_agent_runs_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_runs_started ON public.agent_runs USING btree (started_at DESC);


--
-- Name: idx_agent_schedules_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_schedules_enabled ON public.agent_schedules USING btree (enabled, last_run_at);


--
-- Name: idx_approvals_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approvals_pending ON public.approvals USING btree (status, created_at DESC);


--
-- Name: idx_b2b_conversation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_b2b_conversation_id ON public.b2b_transactions USING btree (conversation_id) WHERE (conversation_id IS NOT NULL);


--
-- Name: idx_b2b_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_b2b_created_at ON public.b2b_transactions USING btree (created_at);


--
-- Name: idx_b2b_reseller_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_b2b_reseller_id ON public.b2b_transactions USING btree (reseller_id);


--
-- Name: idx_cp_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cp_created_at ON public.customer_payments USING btree (created_at DESC);


--
-- Name: idx_cp_lipay_tx_no; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cp_lipay_tx_no ON public.customer_payments USING btree (lipay_tx_no);


--
-- Name: idx_cp_payment_method; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cp_payment_method ON public.customer_payments USING btree (payment_method);


--
-- Name: idx_cp_port_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cp_port_name ON public.customer_payments USING btree (port_name);


--
-- Name: idx_cp_reseller_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cp_reseller_id ON public.customer_payments USING btree (reseller_id);


--
-- Name: idx_device_pairings_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_pairings_customer ON public.device_pairings USING btree (customer_id);


--
-- Name: idx_device_pairings_mac; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_pairings_mac ON public.device_pairings USING btree (device_mac);


--
-- Name: idx_device_pairings_router; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_pairings_router ON public.device_pairings USING btree (router_id);


--
-- Name: idx_mpesa_tx_lipay; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mpesa_tx_lipay ON public.mpesa_transactions USING btree (lipay_tx_no);


--
-- Name: idx_mtn_momo_customer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mtn_momo_customer_id ON public.mtn_momo_transactions USING btree (customer_id);


--
-- Name: idx_mtn_momo_external_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mtn_momo_external_id ON public.mtn_momo_transactions USING btree (external_id);


--
-- Name: idx_mtn_momo_reference_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mtn_momo_reference_id ON public.mtn_momo_transactions USING btree (reference_id);


--
-- Name: idx_mtn_momo_reseller_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mtn_momo_reseller_id ON public.mtn_momo_transactions USING btree (reseller_id);


--
-- Name: idx_mtn_momo_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mtn_momo_status ON public.mtn_momo_transactions USING btree (status);


--
-- Name: idx_portal_settings_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_portal_settings_user ON public.portal_settings USING btree (user_id);


--
-- Name: idx_provisioning_attempt_state_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provisioning_attempt_state_updated ON public.provisioning_attempts USING btree (provisioning_state, updated_at);


--
-- Name: idx_provisioning_attempts_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provisioning_attempts_customer ON public.provisioning_attempts USING btree (customer_id);


--
-- Name: idx_provisioning_attempts_external_reference; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provisioning_attempts_external_reference ON public.provisioning_attempts USING btree (external_reference);


--
-- Name: idx_provisioning_attempts_source; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_provisioning_attempts_source ON public.provisioning_attempts USING btree (source_table, source_pk);


--
-- Name: idx_provisioning_attempts_state_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provisioning_attempts_state_updated ON public.provisioning_attempts USING btree (provisioning_state, updated_at);


--
-- Name: idx_provisioning_logs_attempt_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provisioning_logs_attempt_id ON public.provisioning_logs USING btree (attempt_id);


--
-- Name: idx_provisioning_tokens_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provisioning_tokens_status ON public.provisioning_tokens USING btree (status);


--
-- Name: idx_provisioning_tokens_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provisioning_tokens_token ON public.provisioning_tokens USING btree (token);


--
-- Name: idx_provisioning_tokens_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_provisioning_tokens_user ON public.provisioning_tokens USING btree (user_id);


--
-- Name: idx_radius_acct_callingstationid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_acct_callingstationid ON public.radius_accounting USING btree (callingstationid);


--
-- Name: idx_radius_acct_nasip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_acct_nasip ON public.radius_accounting USING btree (nasipaddress);


--
-- Name: idx_radius_acct_start; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_acct_start ON public.radius_accounting USING btree (acctstarttime);


--
-- Name: idx_radius_acct_stop; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_acct_stop ON public.radius_accounting USING btree (acctstoptime);


--
-- Name: idx_radius_acct_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_radius_acct_unique ON public.radius_accounting USING btree (acctuniqueid);


--
-- Name: idx_radius_acct_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_acct_username ON public.radius_accounting USING btree (username);


--
-- Name: idx_radius_check_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_check_customer ON public.radius_check USING btree (customer_id);


--
-- Name: idx_radius_check_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_check_username ON public.radius_check USING btree (username);


--
-- Name: idx_radius_groupcheck_groupname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_groupcheck_groupname ON public.radius_groupcheck USING btree (groupname);


--
-- Name: idx_radius_groupreply_groupname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_groupreply_groupname ON public.radius_groupreply USING btree (groupname);


--
-- Name: idx_radius_nas_nasname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_nas_nasname ON public.radius_nas USING btree (nasname);


--
-- Name: idx_radius_postauth_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_postauth_date ON public.radius_postauth USING btree (authdate);


--
-- Name: idx_radius_postauth_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_postauth_username ON public.radius_postauth USING btree (username);


--
-- Name: idx_radius_reply_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_reply_customer ON public.radius_reply USING btree (customer_id);


--
-- Name: idx_radius_reply_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_reply_username ON public.radius_reply USING btree (username);


--
-- Name: idx_radius_usergroup_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_radius_usergroup_username ON public.radius_usergroup USING btree (username);


--
-- Name: idx_reconnect_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reconnect_created ON public.reconnection_attempts USING btree (created_at);


--
-- Name: idx_reconnect_mac; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reconnect_mac ON public.reconnection_attempts USING btree (mac_address);


--
-- Name: idx_reconnect_phone; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reconnect_phone ON public.reconnection_attempts USING btree (phone);


--
-- Name: idx_reseller_payouts_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reseller_payouts_created ON public.reseller_payouts USING btree (created_at DESC);


--
-- Name: idx_reseller_payouts_reseller; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reseller_payouts_reseller ON public.reseller_payouts USING btree (reseller_id);


--
-- Name: idx_router_availability_router_checked; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_router_availability_router_checked ON public.router_availability_checks USING btree (router_id, checked_at);


--
-- Name: idx_shop_order_items_order; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shop_order_items_order ON public.shop_order_items USING btree (order_id);


--
-- Name: idx_shop_orders_number; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shop_orders_number ON public.shop_orders USING btree (order_number);


--
-- Name: idx_shop_orders_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shop_orders_user ON public.shop_orders USING btree (user_id);


--
-- Name: idx_shop_products_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shop_products_active ON public.shop_products USING btree (is_active);


--
-- Name: idx_shop_products_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shop_products_user ON public.shop_products USING btree (user_id);


--
-- Name: idx_shop_tracking_order; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_shop_tracking_order ON public.shop_order_tracking USING btree (order_id);


--
-- Name: idx_sub_invoices_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sub_invoices_due ON public.subscription_invoices USING btree (due_date);


--
-- Name: idx_sub_invoices_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sub_invoices_status ON public.subscription_invoices USING btree (status);


--
-- Name: idx_sub_invoices_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sub_invoices_user ON public.subscription_invoices USING btree (user_id);


--
-- Name: idx_sub_payments_checkout; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_sub_payments_checkout ON public.subscription_payments USING btree (mpesa_checkout_request_id) WHERE (mpesa_checkout_request_id IS NOT NULL);


--
-- Name: idx_sub_payments_invoice; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sub_payments_invoice ON public.subscription_payments USING btree (invoice_id);


--
-- Name: idx_sub_payments_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sub_payments_user ON public.subscription_payments USING btree (user_id);


--
-- Name: idx_upm_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_upm_active ON public.user_payment_methods USING btree (user_id, is_active) WHERE (is_active = true);


--
-- Name: idx_upm_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_upm_user_id ON public.user_payment_methods USING btree (user_id);


--
-- Name: idx_vouchers_batch; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vouchers_batch ON public.vouchers USING btree (batch_id);


--
-- Name: idx_vouchers_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vouchers_code ON public.vouchers USING btree (code);


--
-- Name: idx_vouchers_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vouchers_status ON public.vouchers USING btree (status);


--
-- Name: idx_vouchers_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_vouchers_user ON public.vouchers USING btree (user_id);


--
-- Name: idx_work_items_status_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_work_items_status_priority ON public.work_items USING btree (status, priority DESC, created_at DESC);


--
-- Name: ix_ad_clicks_ad_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ad_clicks_ad_id ON public.ad_clicks USING btree (ad_id);


--
-- Name: ix_ad_clicks_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ad_clicks_created_at ON public.ad_clicks USING btree (created_at);


--
-- Name: ix_ad_clicks_mac_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ad_clicks_mac_address ON public.ad_clicks USING btree (mac_address);


--
-- Name: ix_ad_clicks_session_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ad_clicks_session_id ON public.ad_clicks USING btree (session_id);


--
-- Name: ix_ad_impressions_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ad_impressions_created_at ON public.ad_impressions USING btree (created_at);


--
-- Name: ix_ad_impressions_session_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ad_impressions_session_id ON public.ad_impressions USING btree (session_id);


--
-- Name: ix_ads_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ads_expires_at ON public.ads USING btree (expires_at);


--
-- Name: ix_ads_is_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ads_is_active ON public.ads USING btree (is_active);


--
-- Name: ix_ads_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ads_priority ON public.ads USING btree (priority);


--
-- Name: ix_agent_runs_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_runs_agent ON public.agent_runs USING btree (agent);


--
-- Name: ix_agent_runs_started_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_runs_started_at ON public.agent_runs USING btree (started_at);


--
-- Name: ix_agent_runs_work_item_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_agent_runs_work_item_id ON public.agent_runs USING btree (work_item_id);


--
-- Name: ix_approvals_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_approvals_created_at ON public.approvals USING btree (created_at);


--
-- Name: ix_approvals_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_approvals_status ON public.approvals USING btree (status);


--
-- Name: ix_approvals_work_item_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_approvals_work_item_id ON public.approvals USING btree (work_item_id);


--
-- Name: ix_b2b_transactions_conversation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_b2b_transactions_conversation_id ON public.b2b_transactions USING btree (conversation_id);


--
-- Name: ix_b2b_transactions_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_b2b_transactions_created_at ON public.b2b_transactions USING btree (created_at);


--
-- Name: ix_b2b_transactions_reseller_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_b2b_transactions_reseller_id ON public.b2b_transactions USING btree (reseller_id);


--
-- Name: ix_bandwidth_snapshots_recorded_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_bandwidth_snapshots_recorded_at ON public.bandwidth_snapshots USING btree (recorded_at);


--
-- Name: ix_c2b_transactions_bill_ref; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_c2b_transactions_bill_ref ON public.c2b_transactions USING btree (bill_ref_number);


--
-- Name: ix_c2b_transactions_bill_ref_number; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_c2b_transactions_bill_ref_number ON public.c2b_transactions USING btree (bill_ref_number);


--
-- Name: ix_c2b_transactions_business_shortcode; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_c2b_transactions_business_shortcode ON public.c2b_transactions USING btree (business_shortcode);


--
-- Name: ix_c2b_transactions_matched_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_c2b_transactions_matched_customer ON public.c2b_transactions USING btree (matched_customer_id);


--
-- Name: ix_c2b_transactions_matched_customer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_c2b_transactions_matched_customer_id ON public.c2b_transactions USING btree (matched_customer_id);


--
-- Name: ix_c2b_transactions_matched_reseller_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_c2b_transactions_matched_reseller_id ON public.c2b_transactions USING btree (matched_reseller_id);


--
-- Name: ix_c2b_transactions_received_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_c2b_transactions_received_at ON public.c2b_transactions USING btree (received_at);


--
-- Name: ix_c2b_transactions_shortcode; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_c2b_transactions_shortcode ON public.c2b_transactions USING btree (business_shortcode);


--
-- Name: ix_c2b_transactions_trans_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_c2b_transactions_trans_id ON public.c2b_transactions USING btree (trans_id);


--
-- Name: ix_customer_ratings_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_customer_ratings_created_at ON public.customer_ratings USING btree (created_at);


--
-- Name: ix_customer_ratings_phone; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_customer_ratings_phone ON public.customer_ratings USING btree (phone);


--
-- Name: ix_customer_usage_periods_closed_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_customer_usage_periods_closed_at ON public.customer_usage_periods USING btree (closed_at);


--
-- Name: ix_customer_usage_periods_customer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_customer_usage_periods_customer_id ON public.customer_usage_periods USING btree (customer_id);


--
-- Name: ix_customer_usage_periods_customer_open; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_customer_usage_periods_customer_open ON public.customer_usage_periods USING btree (customer_id, closed_at);


--
-- Name: ix_customer_usage_periods_period_start; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_customer_usage_periods_period_start ON public.customer_usage_periods USING btree (period_start);


--
-- Name: ix_customers_account_number; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_customers_account_number ON public.customers USING btree (account_number);


--
-- Name: ix_customers_subscription_owner_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_customers_subscription_owner_id ON public.customers USING btree (subscription_owner_id);


--
-- Name: ix_device_pairings_subscription_owner_customer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_device_pairings_subscription_owner_customer_id ON public.device_pairings USING btree (subscription_owner_customer_id);


--
-- Name: ix_feedback_comments_post_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_feedback_comments_post_id ON public.feedback_comments USING btree (post_id);


--
-- Name: ix_feedback_posts_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_feedback_posts_created_at ON public.feedback_posts USING btree (created_at);


--
-- Name: ix_feedback_posts_open_queue; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_feedback_posts_open_queue ON public.feedback_posts USING btree (created_at) WHERE (status <> ALL (ARRAY['fixed'::public.feedbackstatus, 'declined'::public.feedbackstatus, 'duplicate'::public.feedbackstatus, 'spam'::public.feedbackstatus]));


--
-- Name: ix_feedback_posts_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_feedback_posts_status ON public.feedback_posts USING btree (status);


--
-- Name: ix_feedback_posts_user_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_feedback_posts_user_created ON public.feedback_posts USING btree (user_id, created_at);


--
-- Name: ix_feedback_posts_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_feedback_posts_user_id ON public.feedback_posts USING btree (user_id);


--
-- Name: ix_feedback_votes_post_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_feedback_votes_post_id ON public.feedback_votes USING btree (post_id);


--
-- Name: ix_lead_activities_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lead_activities_created_at ON public.lead_activities USING btree (created_at);


--
-- Name: ix_lead_activities_lead_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lead_activities_lead_id ON public.lead_activities USING btree (lead_id);


--
-- Name: ix_lead_follow_ups_due_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lead_follow_ups_due_at ON public.lead_follow_ups USING btree (due_at);


--
-- Name: ix_lead_follow_ups_lead_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_lead_follow_ups_lead_id ON public.lead_follow_ups USING btree (lead_id);


--
-- Name: ix_leads_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_leads_created_at ON public.leads USING btree (created_at);


--
-- Name: ix_leads_next_followup_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_leads_next_followup_at ON public.leads USING btree (next_followup_at);


--
-- Name: ix_leads_source_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_leads_source_id ON public.leads USING btree (source_id);


--
-- Name: ix_leads_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_leads_user_id ON public.leads USING btree (user_id);


--
-- Name: ix_message_templates_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_message_templates_user_id ON public.message_templates USING btree (user_id);


--
-- Name: ix_mpesa_transactions_checkout_request_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_mpesa_transactions_checkout_request_id ON public.mpesa_transactions USING btree (checkout_request_id);


--
-- Name: ix_mpesa_transactions_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mpesa_transactions_id ON public.mpesa_transactions USING btree (id);


--
-- Name: ix_password_reset_tokens_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_password_reset_tokens_user_id ON public.password_reset_tokens USING btree (user_id);


--
-- Name: ix_provisioning_attempts_customer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provisioning_attempts_customer_id ON public.provisioning_attempts USING btree (customer_id);


--
-- Name: ix_provisioning_attempts_external_reference; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provisioning_attempts_external_reference ON public.provisioning_attempts USING btree (external_reference);


--
-- Name: ix_provisioning_attempts_mac_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provisioning_attempts_mac_address ON public.provisioning_attempts USING btree (mac_address);


--
-- Name: ix_provisioning_attempts_router_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_provisioning_attempts_router_id ON public.provisioning_attempts USING btree (router_id);


--
-- Name: ix_reseller_inbox_messages_recipient_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_reseller_inbox_messages_recipient_user_id ON public.reseller_inbox_messages USING btree (recipient_user_id);


--
-- Name: ix_reseller_payment_methods_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_reseller_payment_methods_user_id ON public.reseller_payment_methods USING btree (user_id);


--
-- Name: ix_reseller_transaction_charges_reseller_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_reseller_transaction_charges_reseller_id ON public.reseller_transaction_charges USING btree (reseller_id);


--
-- Name: ix_router_availability_checks_checked_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_router_availability_checks_checked_at ON public.router_availability_checks USING btree (checked_at);


--
-- Name: ix_router_availability_checks_is_online; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_router_availability_checks_is_online ON public.router_availability_checks USING btree (is_online);


--
-- Name: ix_router_availability_checks_router_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_router_availability_checks_router_id ON public.router_availability_checks USING btree (router_id);


--
-- Name: ix_router_log_entries_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_router_log_entries_created_at ON public.router_log_entries USING btree (created_at);


--
-- Name: ix_router_log_entries_router_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_router_log_entries_router_id ON public.router_log_entries USING btree (router_id);


--
-- Name: ix_router_log_entries_topic; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_router_log_entries_topic ON public.router_log_entries USING btree (topic);


--
-- Name: ix_router_log_entries_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_router_log_entries_username ON public.router_log_entries USING btree (username);


--
-- Name: ix_router_usage_buckets_bucket_start; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_router_usage_buckets_bucket_start ON public.router_usage_buckets USING btree (bucket_start);


--
-- Name: ix_router_usage_buckets_router_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_router_usage_buckets_router_id ON public.router_usage_buckets USING btree (router_id);


--
-- Name: ix_sms_campaigns_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sms_campaigns_user_id ON public.sms_campaigns USING btree (user_id);


--
-- Name: ix_sms_credit_orders_mpesa_checkout_request_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sms_credit_orders_mpesa_checkout_request_id ON public.sms_credit_orders USING btree (mpesa_checkout_request_id);


--
-- Name: ix_sms_credit_orders_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sms_credit_orders_user_id ON public.sms_credit_orders USING btree (user_id);


--
-- Name: ix_sms_credit_transactions_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sms_credit_transactions_created_at ON public.sms_credit_transactions USING btree (created_at);


--
-- Name: ix_sms_credit_transactions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sms_credit_transactions_user_id ON public.sms_credit_transactions USING btree (user_id);


--
-- Name: ix_sms_messages_campaign_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sms_messages_campaign_id ON public.sms_messages USING btree (campaign_id);


--
-- Name: ix_sms_messages_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sms_messages_created_at ON public.sms_messages USING btree (created_at);


--
-- Name: ix_sms_messages_failed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sms_messages_failed ON public.sms_messages USING btree (created_at) WHERE (status = 'failed'::public.smsmessagestatus);


--
-- Name: ix_subscription_share_codes_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_subscription_share_codes_code ON public.subscription_share_codes USING btree (code);


--
-- Name: ix_subscription_share_codes_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_subscription_share_codes_expires_at ON public.subscription_share_codes USING btree (expires_at);


--
-- Name: ix_subscription_share_codes_owner_customer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_subscription_share_codes_owner_customer_id ON public.subscription_share_codes USING btree (owner_customer_id);


--
-- Name: ix_subscription_share_codes_redeemed_customer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_subscription_share_codes_redeemed_customer_id ON public.subscription_share_codes USING btree (redeemed_customer_id);


--
-- Name: ix_subscription_share_codes_redeemed_pairing_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_subscription_share_codes_redeemed_pairing_id ON public.subscription_share_codes USING btree (redeemed_pairing_id);


--
-- Name: ix_subscription_share_codes_router_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_subscription_share_codes_router_id ON public.subscription_share_codes USING btree (router_id);


--
-- Name: ix_subscription_share_codes_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_subscription_share_codes_status ON public.subscription_share_codes USING btree (status);


--
-- Name: ix_unmatched_c2b_assigned_reseller; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_unmatched_c2b_assigned_reseller ON public.unmatched_c2b_payments USING btree (assigned_reseller_id);


--
-- Name: ix_unmatched_c2b_payments_assigned_reseller_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_unmatched_c2b_payments_assigned_reseller_id ON public.unmatched_c2b_payments USING btree (assigned_reseller_id);


--
-- Name: ix_usage_cap_watch_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_cap_watch_due ON public.usage_cap_watch_state USING btree (next_poll_at, router_id);


--
-- Name: ix_usage_cap_watch_router_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_cap_watch_router_due ON public.usage_cap_watch_state USING btree (router_id, next_poll_at);


--
-- Name: ix_usage_cap_watch_state_backoff_until; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_cap_watch_state_backoff_until ON public.usage_cap_watch_state USING btree (backoff_until);


--
-- Name: ix_usage_cap_watch_state_customer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_cap_watch_state_customer_id ON public.usage_cap_watch_state USING btree (customer_id);


--
-- Name: ix_usage_cap_watch_state_next_poll_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_cap_watch_state_next_poll_at ON public.usage_cap_watch_state USING btree (next_poll_at);


--
-- Name: ix_usage_cap_watch_state_queue_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_cap_watch_state_queue_key ON public.usage_cap_watch_state USING btree (queue_key);


--
-- Name: ix_usage_cap_watch_state_router_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_usage_cap_watch_state_router_id ON public.usage_cap_watch_state USING btree (router_id);


--
-- Name: ix_user_bandwidth_usage_last_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_user_bandwidth_usage_last_updated ON public.user_bandwidth_usage USING btree (last_updated);


--
-- Name: ix_user_bandwidth_usage_mac_address; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_user_bandwidth_usage_mac_address ON public.user_bandwidth_usage USING btree (mac_address);


--
-- Name: ix_work_items_code; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_work_items_code ON public.work_items USING btree (code);


--
-- Name: ix_work_items_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_work_items_created_at ON public.work_items USING btree (created_at);


--
-- Name: ix_work_items_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_work_items_status ON public.work_items USING btree (status);


--
-- Name: ix_zenopay_transactions_customer_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_zenopay_transactions_customer_id ON public.zenopay_transactions USING btree (customer_id);


--
-- Name: ix_zenopay_transactions_order_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_zenopay_transactions_order_id ON public.zenopay_transactions USING btree (order_id);


--
-- Name: ix_zenopay_transactions_reseller_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_zenopay_transactions_reseller_id ON public.zenopay_transactions USING btree (reseller_id);


--
-- Name: access_credentials access_credentials_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_credentials
    ADD CONSTRAINT access_credentials_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id);


--
-- Name: access_credentials access_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_credentials
    ADD CONSTRAINT access_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: ad_clicks ad_clicks_ad_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ad_clicks
    ADD CONSTRAINT ad_clicks_ad_id_fkey FOREIGN KEY (ad_id) REFERENCES public.ads(id);


--
-- Name: ads ads_advertiser_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ads
    ADD CONSTRAINT ads_advertiser_id_fkey FOREIGN KEY (advertiser_id) REFERENCES public.advertisers(id);


--
-- Name: agent_runs agent_runs_work_item_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_runs
    ADD CONSTRAINT agent_runs_work_item_id_fkey FOREIGN KEY (work_item_id) REFERENCES public.work_items(id) ON DELETE SET NULL;


--
-- Name: approvals approvals_work_item_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approvals
    ADD CONSTRAINT approvals_work_item_id_fkey FOREIGN KEY (work_item_id) REFERENCES public.work_items(id) ON DELETE SET NULL;


--
-- Name: b2b_transactions b2b_transactions_charge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.b2b_transactions
    ADD CONSTRAINT b2b_transactions_charge_id_fkey FOREIGN KEY (charge_id) REFERENCES public.reseller_transaction_charges(id);


--
-- Name: b2b_transactions b2b_transactions_payout_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.b2b_transactions
    ADD CONSTRAINT b2b_transactions_payout_id_fkey FOREIGN KEY (payout_id) REFERENCES public.reseller_payouts(id);


--
-- Name: b2b_transactions b2b_transactions_reseller_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.b2b_transactions
    ADD CONSTRAINT b2b_transactions_reseller_id_fkey FOREIGN KEY (reseller_id) REFERENCES public.users(id);


--
-- Name: bandwidth_snapshots bandwidth_snapshots_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bandwidth_snapshots
    ADD CONSTRAINT bandwidth_snapshots_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id);


--
-- Name: c2b_transactions c2b_transactions_matched_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.c2b_transactions
    ADD CONSTRAINT c2b_transactions_matched_customer_id_fkey FOREIGN KEY (matched_customer_id) REFERENCES public.customers(id);


--
-- Name: c2b_transactions c2b_transactions_matched_reseller_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.c2b_transactions
    ADD CONSTRAINT c2b_transactions_matched_reseller_id_fkey FOREIGN KEY (matched_reseller_id) REFERENCES public.users(id);


--
-- Name: customer_payments customer_payments_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_payments
    ADD CONSTRAINT customer_payments_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: customer_payments customer_payments_reseller_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_payments
    ADD CONSTRAINT customer_payments_reseller_id_fkey FOREIGN KEY (reseller_id) REFERENCES public.users(id);


--
-- Name: customer_ratings customer_ratings_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_ratings
    ADD CONSTRAINT customer_ratings_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: customer_usage_periods customer_usage_periods_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_usage_periods
    ADD CONSTRAINT customer_usage_periods_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: customers customers_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_plan_id_fkey FOREIGN KEY (plan_id) REFERENCES public.plans(id);


--
-- Name: customers customers_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id);


--
-- Name: customers customers_subscription_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_subscription_owner_id_fkey FOREIGN KEY (subscription_owner_id) REFERENCES public.customers(id) ON DELETE SET NULL;


--
-- Name: customers customers_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: device_pairings device_pairings_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_pairings
    ADD CONSTRAINT device_pairings_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: device_pairings device_pairings_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_pairings
    ADD CONSTRAINT device_pairings_plan_id_fkey FOREIGN KEY (plan_id) REFERENCES public.plans(id);


--
-- Name: device_pairings device_pairings_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_pairings
    ADD CONSTRAINT device_pairings_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id);


--
-- Name: device_pairings device_pairings_subscription_owner_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_pairings
    ADD CONSTRAINT device_pairings_subscription_owner_customer_id_fkey FOREIGN KEY (subscription_owner_customer_id) REFERENCES public.customers(id) ON DELETE SET NULL;


--
-- Name: feedback_comments feedback_comments_post_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_comments
    ADD CONSTRAINT feedback_comments_post_id_fkey FOREIGN KEY (post_id) REFERENCES public.feedback_posts(id) ON DELETE CASCADE;


--
-- Name: feedback_comments feedback_comments_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_comments
    ADD CONSTRAINT feedback_comments_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: feedback_posts feedback_posts_ai_duplicate_of_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_posts
    ADD CONSTRAINT feedback_posts_ai_duplicate_of_id_fkey FOREIGN KEY (ai_duplicate_of_id) REFERENCES public.feedback_posts(id) ON DELETE SET NULL;


--
-- Name: feedback_posts feedback_posts_duplicate_of_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_posts
    ADD CONSTRAINT feedback_posts_duplicate_of_id_fkey FOREIGN KEY (duplicate_of_id) REFERENCES public.feedback_posts(id) ON DELETE SET NULL;


--
-- Name: feedback_posts feedback_posts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_posts
    ADD CONSTRAINT feedback_posts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: feedback_votes feedback_votes_post_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_votes
    ADD CONSTRAINT feedback_votes_post_id_fkey FOREIGN KEY (post_id) REFERENCES public.feedback_posts(id) ON DELETE CASCADE;


--
-- Name: feedback_votes feedback_votes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feedback_votes
    ADD CONSTRAINT feedback_votes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: customer_payments fk_customer_payments_plan_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.customer_payments
    ADD CONSTRAINT fk_customer_payments_plan_id FOREIGN KEY (plan_id) REFERENCES public.plans(id) ON DELETE SET NULL;


--
-- Name: mpesa_transactions fk_mpesa_transactions_plan_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mpesa_transactions
    ADD CONSTRAINT fk_mpesa_transactions_plan_id FOREIGN KEY (plan_id) REFERENCES public.plans(id) ON DELETE SET NULL;


--
-- Name: provisioning_logs fk_provisioning_logs_attempt_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_logs
    ADD CONSTRAINT fk_provisioning_logs_attempt_id FOREIGN KEY (attempt_id) REFERENCES public.provisioning_attempts(id);


--
-- Name: lead_activities lead_activities_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_activities
    ADD CONSTRAINT lead_activities_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: lead_activities lead_activities_lead_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_activities
    ADD CONSTRAINT lead_activities_lead_id_fkey FOREIGN KEY (lead_id) REFERENCES public.leads(id) ON DELETE CASCADE;


--
-- Name: lead_follow_ups lead_follow_ups_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_follow_ups
    ADD CONSTRAINT lead_follow_ups_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: lead_follow_ups lead_follow_ups_lead_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_follow_ups
    ADD CONSTRAINT lead_follow_ups_lead_id_fkey FOREIGN KEY (lead_id) REFERENCES public.leads(id) ON DELETE CASCADE;


--
-- Name: lead_sources lead_sources_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_sources
    ADD CONSTRAINT lead_sources_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: leads leads_converted_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.leads
    ADD CONSTRAINT leads_converted_user_id_fkey FOREIGN KEY (converted_user_id) REFERENCES public.users(id);


--
-- Name: leads leads_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.leads
    ADD CONSTRAINT leads_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.lead_sources(id);


--
-- Name: leads leads_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.leads
    ADD CONSTRAINT leads_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: message_templates message_templates_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_templates
    ADD CONSTRAINT message_templates_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: mpesa_transactions mpesa_transactions_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mpesa_transactions
    ADD CONSTRAINT mpesa_transactions_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: mtn_momo_transactions mtn_momo_transactions_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mtn_momo_transactions
    ADD CONSTRAINT mtn_momo_transactions_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: mtn_momo_transactions mtn_momo_transactions_reseller_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mtn_momo_transactions
    ADD CONSTRAINT mtn_momo_transactions_reseller_id_fkey FOREIGN KEY (reseller_id) REFERENCES public.users(id);


--
-- Name: password_reset_tokens password_reset_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: payments payments_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: plans plans_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plans
    ADD CONSTRAINT plans_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: portal_settings portal_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.portal_settings
    ADD CONSTRAINT portal_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: provisioning_attempts provisioning_attempts_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_attempts
    ADD CONSTRAINT provisioning_attempts_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: provisioning_attempts provisioning_attempts_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_attempts
    ADD CONSTRAINT provisioning_attempts_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id);


--
-- Name: provisioning_logs provisioning_logs_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_logs
    ADD CONSTRAINT provisioning_logs_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: provisioning_logs provisioning_logs_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_logs
    ADD CONSTRAINT provisioning_logs_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id);


--
-- Name: provisioning_tokens provisioning_tokens_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_tokens
    ADD CONSTRAINT provisioning_tokens_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id);


--
-- Name: provisioning_tokens provisioning_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.provisioning_tokens
    ADD CONSTRAINT provisioning_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: radius_check radius_check_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_check
    ADD CONSTRAINT radius_check_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id) ON DELETE CASCADE;


--
-- Name: radius_nas radius_nas_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_nas
    ADD CONSTRAINT radius_nas_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id) ON DELETE CASCADE;


--
-- Name: radius_reply radius_reply_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radius_reply
    ADD CONSTRAINT radius_reply_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id) ON DELETE CASCADE;


--
-- Name: reconnection_attempts reconnection_attempts_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reconnection_attempts
    ADD CONSTRAINT reconnection_attempts_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: reconnection_attempts reconnection_attempts_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reconnection_attempts
    ADD CONSTRAINT reconnection_attempts_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id);


--
-- Name: reseller_financials reseller_financials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_financials
    ADD CONSTRAINT reseller_financials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: reseller_inbox_messages reseller_inbox_messages_recipient_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_inbox_messages
    ADD CONSTRAINT reseller_inbox_messages_recipient_user_id_fkey FOREIGN KEY (recipient_user_id) REFERENCES public.users(id);


--
-- Name: reseller_inbox_messages reseller_inbox_messages_sender_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_inbox_messages
    ADD CONSTRAINT reseller_inbox_messages_sender_user_id_fkey FOREIGN KEY (sender_user_id) REFERENCES public.users(id);


--
-- Name: reseller_payment_methods reseller_payment_methods_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_payment_methods
    ADD CONSTRAINT reseller_payment_methods_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: reseller_payouts reseller_payouts_reseller_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_payouts
    ADD CONSTRAINT reseller_payouts_reseller_id_fkey FOREIGN KEY (reseller_id) REFERENCES public.users(id);


--
-- Name: reseller_transaction_charges reseller_transaction_charges_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_transaction_charges
    ADD CONSTRAINT reseller_transaction_charges_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: reseller_transaction_charges reseller_transaction_charges_reseller_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reseller_transaction_charges
    ADD CONSTRAINT reseller_transaction_charges_reseller_id_fkey FOREIGN KEY (reseller_id) REFERENCES public.users(id);


--
-- Name: router_availability_checks router_availability_checks_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.router_availability_checks
    ADD CONSTRAINT router_availability_checks_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id) ON DELETE RESTRICT;


--
-- Name: router_log_entries router_log_entries_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.router_log_entries
    ADD CONSTRAINT router_log_entries_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id);


--
-- Name: router_usage_buckets router_usage_buckets_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.router_usage_buckets
    ADD CONSTRAINT router_usage_buckets_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id);


--
-- Name: routers routers_payment_method_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.routers
    ADD CONSTRAINT routers_payment_method_id_fkey FOREIGN KEY (payment_method_id) REFERENCES public.reseller_payment_methods(id);


--
-- Name: routers routers_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.routers
    ADD CONSTRAINT routers_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: shop_order_items shop_order_items_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_order_items
    ADD CONSTRAINT shop_order_items_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.shop_orders(id) ON DELETE CASCADE;


--
-- Name: shop_order_items shop_order_items_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_order_items
    ADD CONSTRAINT shop_order_items_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.shop_products(id);


--
-- Name: shop_order_tracking shop_order_tracking_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_order_tracking
    ADD CONSTRAINT shop_order_tracking_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.shop_orders(id) ON DELETE CASCADE;


--
-- Name: shop_order_tracking shop_order_tracking_updated_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_order_tracking
    ADD CONSTRAINT shop_order_tracking_updated_by_user_id_fkey FOREIGN KEY (updated_by_user_id) REFERENCES public.users(id);


--
-- Name: shop_orders shop_orders_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_orders
    ADD CONSTRAINT shop_orders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: shop_products shop_products_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shop_products
    ADD CONSTRAINT shop_products_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: sms_campaigns sms_campaigns_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_campaigns
    ADD CONSTRAINT sms_campaigns_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: sms_credit_accounts sms_credit_accounts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_credit_accounts
    ADD CONSTRAINT sms_credit_accounts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: sms_credit_orders sms_credit_orders_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_credit_orders
    ADD CONSTRAINT sms_credit_orders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: sms_credit_transactions sms_credit_transactions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_credit_transactions
    ADD CONSTRAINT sms_credit_transactions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: sms_messages sms_messages_campaign_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_messages
    ADD CONSTRAINT sms_messages_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES public.sms_campaigns(id);


--
-- Name: sms_messages sms_messages_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_messages
    ADD CONSTRAINT sms_messages_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: sms_messages sms_messages_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sms_messages
    ADD CONSTRAINT sms_messages_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: subscription_invoices subscription_invoices_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_invoices
    ADD CONSTRAINT subscription_invoices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: subscription_payments subscription_payments_invoice_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_payments
    ADD CONSTRAINT subscription_payments_invoice_id_fkey FOREIGN KEY (invoice_id) REFERENCES public.subscription_invoices(id);


--
-- Name: subscription_payments subscription_payments_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_payments
    ADD CONSTRAINT subscription_payments_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: subscription_share_codes subscription_share_codes_owner_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_share_codes
    ADD CONSTRAINT subscription_share_codes_owner_customer_id_fkey FOREIGN KEY (owner_customer_id) REFERENCES public.customers(id) ON DELETE CASCADE;


--
-- Name: subscription_share_codes subscription_share_codes_redeemed_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_share_codes
    ADD CONSTRAINT subscription_share_codes_redeemed_customer_id_fkey FOREIGN KEY (redeemed_customer_id) REFERENCES public.customers(id) ON DELETE SET NULL;


--
-- Name: subscription_share_codes subscription_share_codes_redeemed_pairing_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_share_codes
    ADD CONSTRAINT subscription_share_codes_redeemed_pairing_id_fkey FOREIGN KEY (redeemed_pairing_id) REFERENCES public.device_pairings(id) ON DELETE SET NULL;


--
-- Name: subscription_share_codes subscription_share_codes_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscription_share_codes
    ADD CONSTRAINT subscription_share_codes_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id) ON DELETE CASCADE;


--
-- Name: subscriptions subscriptions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: unmatched_c2b_payments unmatched_c2b_payments_assigned_reseller_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unmatched_c2b_payments
    ADD CONSTRAINT unmatched_c2b_payments_assigned_reseller_id_fkey FOREIGN KEY (assigned_reseller_id) REFERENCES public.users(id);


--
-- Name: unmatched_c2b_payments unmatched_c2b_payments_c2b_transaction_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unmatched_c2b_payments
    ADD CONSTRAINT unmatched_c2b_payments_c2b_transaction_id_fkey FOREIGN KEY (c2b_transaction_id) REFERENCES public.c2b_transactions(id);


--
-- Name: unmatched_c2b_payments unmatched_c2b_payments_resolution_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unmatched_c2b_payments
    ADD CONSTRAINT unmatched_c2b_payments_resolution_customer_id_fkey FOREIGN KEY (resolution_customer_id) REFERENCES public.customers(id);


--
-- Name: unmatched_c2b_payments unmatched_c2b_payments_resolved_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.unmatched_c2b_payments
    ADD CONSTRAINT unmatched_c2b_payments_resolved_by_user_id_fkey FOREIGN KEY (resolved_by_user_id) REFERENCES public.users(id);


--
-- Name: usage_cap_watch_state usage_cap_watch_state_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_cap_watch_state
    ADD CONSTRAINT usage_cap_watch_state_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: usage_cap_watch_state usage_cap_watch_state_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_cap_watch_state
    ADD CONSTRAINT usage_cap_watch_state_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id);


--
-- Name: user_bandwidth_usage user_bandwidth_usage_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_bandwidth_usage
    ADD CONSTRAINT user_bandwidth_usage_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: user_payment_methods user_payment_methods_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_payment_methods
    ADD CONSTRAINT user_payment_methods_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: users users_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: vouchers vouchers_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vouchers
    ADD CONSTRAINT vouchers_plan_id_fkey FOREIGN KEY (plan_id) REFERENCES public.plans(id);


--
-- Name: vouchers vouchers_redeemed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vouchers
    ADD CONSTRAINT vouchers_redeemed_by_fkey FOREIGN KEY (redeemed_by) REFERENCES public.customers(id);


--
-- Name: vouchers vouchers_router_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vouchers
    ADD CONSTRAINT vouchers_router_id_fkey FOREIGN KEY (router_id) REFERENCES public.routers(id);


--
-- Name: vouchers vouchers_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vouchers
    ADD CONSTRAINT vouchers_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: zenopay_transactions zenopay_transactions_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zenopay_transactions
    ADD CONSTRAINT zenopay_transactions_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.customers(id);


--
-- Name: zenopay_transactions zenopay_transactions_reseller_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.zenopay_transactions
    ADD CONSTRAINT zenopay_transactions_reseller_id_fkey FOREIGN KEY (reseller_id) REFERENCES public.users(id);


--
-- PostgreSQL database dump complete
--

\unrestrict TIkuTftwQGI9FIC0dTq7vm1lGyA8r9Tefct4cAx3FaDqRbGyUX4qrFjt1SFvBRr

