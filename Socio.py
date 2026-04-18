"""Socio.py

Flask application for social media OSINT endpoints and Discord alert delivery.
This module contains Twitter and Reddit lookup routes, AI analysis stubs, and
Discord webhook/bot forwarding utilities.
"""
from flask import Flask, render_template, jsonify, redirect, url_for, session, request
import base64
import json
import logging
import os
import random
import re
import sqlite3
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from functools import wraps

import requests
from celery import Celery
from flask import (
    Flask,
    jsonify,
    request,
    session,
)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from textblob import TextBlob
except ImportError:
    TextBlob = None

try:
    from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
    sia = SentimentIntensityAnalyzer()
except ImportError:
    sia = None

toxicity_pipeline = None
nlp = None
TfidfVectorizer = None

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "your-secret-key-here")
app.config["CELERY_BROKER_URL"] = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
app.config["CELERY_RESULT_BACKEND"] = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")


celery = Celery(app.name, broker=app.config["CELERY_BROKER_URL"])
celery.conf.update(app.config)

TWITTER_CONSUMER_KEY = os.environ.get("TWITTER_CONSUMER_KEY", "BRING_YOUR_OWN_API_KEY")
TWITTER_CONSUMER_SECRET = os.environ.get("TWITTER_CONSUMER_SECRET", "BRING_YOUR_OWN_API_KEY")
TWITTER_BEARER_TOKEN = os.environ.get("TWITTER_BEARER_TOKEN", "BRING_YOUR_OWN_API_KEY")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

# -----------------------------------------------------------------
# 1. Config – Hugging Face setup (free API)
# -----------------------------------------------------------------
HF_TOKEN = os.environ.get("HF_TOKEN", "")
if not HF_TOKEN:
    logger.warning("HF_TOKEN not set in environment")

HF_URL = "https://router.huggingface.co/v1/chat/completions"
HEADERS = {"Authorization": f"Bearer {HF_TOKEN}", "Content-Type": "application/json"}
MODEL_ID = "meta-llama/Llama-3.1-8B-Instruct:cerebras"


OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama-2")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "YOUR_DISCORD_WEBHOOK")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "BRING_YOUR_OWN_API_KEY")
DB_FILE = os.environ.get("SOCIO_DB_FILE", os.path.join(os.path.dirname(__file__), "socio.db"))

def get_conn():
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = get_conn()
    c = conn.cursor()

    # Reddit Monitoring Tables
    c.execute('''CREATE TABLE IF NOT EXISTS reddit_monitors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_name TEXT NOT NULL UNIQUE,
                    target_type TEXT NOT NULL,
                    threat_tier TEXT DEFAULT 'LOW',
                    threat_score REAL DEFAULT 0,
                    status TEXT DEFAULT 'IDLE',
                    webhook_url TEXT,
                    last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_alert TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')

    c.execute('''CREATE TABLE IF NOT EXISTS reddit_intel (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_name TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    search_type TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    
    conn.commit()

    c.execute("SELECT COUNT(*) FROM users")
    count = c.fetchone()[0]
    conn.close()


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "Authentication required"}), 401
        return fn(*args, **kwargs)
    return wrapper


def get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def get_twitter_bearer_headers():
    return {"Authorization": f"Bearer {TWITTER_BEARER_TOKEN}"}


def normalize_reddit_post(post):
    normalized = {
        "id": post.get("id") or post.get("name", ""),
        "score": int(post.get("score") or post.get("ups") or 0),
        "num_comments": int(post.get("num_comments") or post.get("comments") or 0),
        "subreddit": str(post.get("subreddit") or post.get("subreddit_name_prefixed") or "").replace("r/", "").strip(),
        "author": post.get("author") or post.get("author_name") or "unknown",
        "title": post.get("title") or post.get("headline") or "",
        "selftext": post.get("selftext") or post.get("body") or post.get("text") or "",
        "created_utc": int(post.get("created_utc") or post.get("created") or post.get("created_at") or 0),
    }
    if isinstance(normalized["created_utc"], str):
        try:
            normalized["created_utc"] = int(float(normalized["created_utc"]))
        except ValueError:
            normalized["created_utc"] = 0
    return normalized


def extract_json_payload(text):
    if not isinstance(text, str):
        return None
    cleaned = re.sub(r"```json|```", "", text).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        json_start = cleaned.find('{')
        json_end = cleaned.rfind('}')
        if json_start != -1 and json_end != -1 and json_end > json_start:
            candidate = cleaned[json_start:json_end + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                return None
        return None


def normalize_reddit_analysis(analysis):
    if not isinstance(analysis, dict):
        return {}

    def safe_int(value, default=0):
        try:
            if isinstance(value, bool):
                return int(value)
            return int(float(value))
        except Exception:
            return default

    def safe_float(value, default=0.0):
        try:
            return float(value)
        except Exception:
            return default

    def ensure_str(value, default='Unknown'):
        if value is None:
            return default
        if isinstance(value, str) and value.strip() == '':
            return default
        return str(value)

    def normal_list(value):
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [json.dumps(value, ensure_ascii=False)]
        return list(value)

    # Handle new Hugging Face format
    if 'sentiment_analysis' in analysis:
        # New simplified format from Hugging Face
        sentiment_analysis = analysis.get('sentiment_analysis', {})
        ideology_analysis = analysis.get('ideology_analysis', {})
        behavioral_insights = analysis.get('behavioral_insights', {})
        risk_assessment = analysis.get('risk_assessment', {})
        personality_profile = analysis.get('personality_profile', {})

        return {
            "demographics": {
                "age_estimate": "Unknown",
                "gender": "Unknown",
                "location": "Unknown",
                "language": "Unknown",
                "timezone": "Unknown"
            },
            "ideology": {
                "primary_ideology": ideology_analysis.get('primary_ideology', ideology_analysis.get('primary', 'Unknown')),
                "confidence": safe_float(ideology_analysis.get('confidence', 0.5)),
                "indicators": normal_list(ideology_analysis.get('key_indicators', ideology_analysis.get('indicators', []))),
                "description": ideology_analysis.get('description') or analysis.get('summary', 'Detailed AI analysis.')
            },
            "occupation_indicators": [],
            "interests": normal_list(personality_profile.get('interests', [])),
            "personality": {
                "mbti": personality_profile.get('communication_style', 'Unknown'),
                "big_five": {
                    "openness": 50,
                    "conscientiousness": 50,
                    "extraversion": 50,
                    "agreeableness": 50,
                    "neuroticism": 50
                }
            },
            "behavioral_patterns": behavioral_insights.get('posting_patterns', 'Unknown'),
            "content_themes": normal_list(behavioral_insights.get('content_themes', [])),
            "layer_1_sentiment_ideology": {
                "scores": {
                    "pos": 0.0,
                    "neg": 0.0,
                    "neu": 1.0
                },
                "ideology": ideology_analysis.get('primary_ideology', 'Unknown'),
                "affect": sentiment_analysis.get('emotional_tone', 'Neutral'),
                "signals": {
                    "outrage": 0,
                    "fear": 0,
                    "hope": 0
                }
            },
            "layer_2_narrative_stance": {
                "framing": behavioral_insights.get('posting_patterns', 'Unknown'),
                "stance": ideology_analysis.get('political_leaning', 'center').title(),
                "us_vs_them": "Unknown"
            },
            "layer_3_behavioral_analysis": {
                "account_signals": behavioral_insights.get('activity_level', 'medium').title() + " activity detected",
                "karma_velocity": behavioral_insights.get('activity_level', 'medium').title(),
                "burst_posting": "Unknown",
                "dormancy_patterns": "Active posting pattern",
                "temporal": "Unknown",
                "coordinated_timing": "No",
                "event_linked_spikes": "No",
                "content_patterns": behavioral_insights.get('posting_patterns', 'Unknown'),
                "copy_paste_ratio": "Unknown",
                "lexical_diversity_score": 0,
                "edit_frequency": "Unknown",
                "reply_speed_under_60s": "Unknown",
                "same_subreddit_loops": "Unknown",
                "link_domain_bias": "Unknown",
                "bot_indicators": {"score": 0, "flags": []}
            },
            "layer_4_network_structure_sna": {
                "influence": behavioral_insights.get('community_engagement', 'Unknown'),
                "cascade": "Unknown",
                "metrics": {"betweenness": 0.0, "clustering": 0.0},
                "community_detect": "Unknown",
                "bridge_node_id": "Unknown",
                "amplifier_accounts": [],
                "cross_sub_migration_flow_vectors": "Unknown"
            },
            "layer_5_threat_political_status": {
                "threat_level": risk_assessment.get('threat_level', 'low').upper(),
                "threat_score": 0,
                "narratives": risk_assessment.get('concerning_signals', 'No concerns identified'),
                "interference": "No signals detected",
                "protest": "No signals detected",
                "foreign_actor_fingerprints": "Unknown",
                "mnc_institutional_brand_reputation_shifts": "Unknown",
                "employee_sentiment_leak": "Unknown",
                "coordinated_corp_attack": "No",
                "policy_pressure_campaigns": "No",
                "political_status": ideology_analysis.get('political_leaning', 'center').title(),
                "party_sentiment_delta": 0.0,
                "topic_salience_ranking": [],
                "astroturf_confidence_score": 0,
                "crisis_escalation_index": 0
            },
            "sentiment": {
                "overall": sentiment_analysis.get('overall_sentiment', 'neutral'),
                "score": safe_float(sentiment_analysis.get('sentiment_score', 0.0), 0.0),
                "tone": sentiment_analysis.get('emotional_tone', 'Neutral')
            },
            "score": {
                "influence": 0,
                "trust": 0,
                "activity": 0,
                "engagement": 0,
                "overall": 0
            },
            "red_flags": risk_assessment.get('risk_factors', []),
            "assessment": analysis.get('summary', 'AI analysis completed'),
            "raw_output": analysis
        }

    # Handle legacy complex format (existing code)
    demographics = analysis.get('demographics', {}) or {}
    personality = analysis.get('personality', {}) or {}
    big_five = personality.get('big_five') or personality.get('bigFive') or {}
    if not isinstance(big_five, dict):
        big_five = {}

    scores = analysis.get('score') or analysis.get('scores') or {}
    if not isinstance(scores, dict):
        scores = {}

    occupation_indicators = analysis.get('occupation_indicators') or analysis.get('occupation', {}).get('keywords') or []
    occupation_indicators = normal_list(occupation_indicators)

    layer_1 = analysis.get('layer_1_sentiment_ideology') or analysis.get('sentiment_ideology') or {}
    layer_2 = analysis.get('layer_2_narrative_stance') or analysis.get('narrative_stance') or {}
    layer_3 = analysis.get('layer_3_behavioral_analysis') or analysis.get('behavioral_analysis') or {}
    layer_4 = analysis.get('layer_4_network_structure_sna') or analysis.get('network_analysis') or {}
    layer_5 = analysis.get('layer_5_threat_political_status') or analysis.get('threat_analysis') or {}

    # Map legacy threat analysis names into the new Layer 5 schema.
    threat_level = layer_5.get('threat_level') or layer_5.get('national_threat_level') or analysis.get('threat_level') or analysis.get('national_threat_level') or 'LOW'
    threat_score = safe_int(layer_5.get('threat_score') or layer_5.get('score') or analysis.get('threat_score') or 0)
    visibility_narratives = layer_5.get('narratives') or layer_5.get('governance_targeting') or analysis.get('governance_targeting') or ''
    interference = layer_5.get('interference') or layer_5.get('election_interference') or analysis.get('election_interference') or ''
    protest = layer_5.get('protest') or layer_5.get('protest_mobilisation') or analysis.get('protest_mobilisation') or ''
    foreign_actor_fingerprints = layer_5.get('foreign_actor_fingerprints') or layer_5.get('foreign_actor_fp') or analysis.get('foreign_actor_fp') or ''
    brand_shifts = layer_5.get('mnc_institutional_brand_reputation_shifts') or layer_5.get('brand_shifts') or analysis.get('brand_shifts') or ''
    employee_leak = layer_5.get('employee_sentiment_leak') or layer_5.get('employee_leaks') or analysis.get('employee_leaks') or ''
    coordinated_attack = layer_5.get('coordinated_corp_attack') or layer_5.get('coordinated_attack') or analysis.get('coordinated_attack') or ''
    policy_pressure_campaigns = layer_5.get('policy_pressure_campaigns') or layer_5.get('pressure_campaigns') or analysis.get('pressure_campaigns') or ''
    political_status = layer_5.get('political_status') or analysis.get('political_status') or ''
    party_delta = safe_float(layer_5.get('party_sentiment_delta') or layer_5.get('party_delta') or analysis.get('party_delta') or 0)
    astroturf_confidence_score = safe_int(layer_5.get('astroturf_confidence_score') or layer_5.get('astroturf_confidence') or analysis.get('astroturf_confidence') or 0)
    crisis_escalation_index = safe_int(layer_5.get('crisis_escalation_index') or analysis.get('crisis_escalation_index') or 0)

    bot_indicators = layer_3.get('bot_indicators') or {}
    if not isinstance(bot_indicators, dict):
        bot_indicators = {}
    bot_score = bot_indicators.get('score') if bot_indicators.get('score') is not None else bot_indicators.get('automation_probability') or bot_indicators.get('automation')
    if isinstance(bot_score, float) and 0 <= bot_score <= 1:
        bot_score = int(round(bot_score * 100))
    bot_indicators = {
        "score": safe_int(bot_score, 0),
        "flags": normal_list(bot_indicators.get('flags') or [])
    }

    layer_1_scores = layer_1.get('scores')
    if not isinstance(layer_1_scores, dict):
        layer_1_scores = analysis.get('sentiment') if isinstance(analysis.get('sentiment'), dict) else {}

    return {
        "demographics": {
            "age_estimate": demographics.get('age_estimate', demographics.get('age', 'Unknown')),
            "gender": demographics.get('gender', 'Unknown'),
            "location": demographics.get('location', 'Unknown'),
            "language": demographics.get('language', 'Unknown'),
            "timezone": demographics.get('timezone', 'Unknown')
        },
        "occupation_indicators": occupation_indicators,
        "interests": analysis.get('interests', []) if isinstance(analysis.get('interests', []), list) else normal_list(analysis.get('interests', [])),
        "personality": {
            "mbti": personality.get('mbti') or personality.get('mbti_type') or 'Unknown',
            "big_five": {
                "openness": safe_int(big_five.get('openness') or big_five.get('openness_score') or 0),
                "conscientiousness": safe_int(big_five.get('conscientiousness') or big_five.get('conscientiousness_score') or 0),
                "extraversion": safe_int(big_five.get('extraversion') or big_five.get('extraversion_score') or 0),
                "agreeableness": safe_int(big_five.get('agreeableness') or big_five.get('agreeableness_score') or 0),
                "neuroticism": safe_int(big_five.get('neuroticism') or big_five.get('neuroticism_score') or 0)
            }
        },
        "ideology": {
            "primary_ideology": (analysis.get('ideology') if isinstance(analysis.get('ideology'), dict) else {}).get('primary_ideology') or analysis.get('ideology_details', {}).get('primary_ideology') or (analysis.get('ideology') if isinstance(analysis.get('ideology'), str) else None) or 'Centrist',
            "confidence": safe_float((analysis.get('ideology') if isinstance(analysis.get('ideology'), dict) else {}).get('confidence') or analysis.get('ideology_details', {}).get('confidence') or 0.5, 0.5),
            "indicators": normal_list((analysis.get('ideology') if isinstance(analysis.get('ideology'), dict) else {}).get('indicators') or analysis.get('ideology_details', {}).get('indicators') or []),
            "description": (analysis.get('ideology') if isinstance(analysis.get('ideology'), dict) else {}).get('description') or analysis.get('ideology_details', {}).get('description') or 'Moderate centrist views',
            "scores": (analysis.get('ideology') if isinstance(analysis.get('ideology'), dict) else {}).get('scores') or analysis.get('ideology_details', {}).get('scores') or {}
        },
        "behavioral_patterns": analysis.get('behavioral_patterns') or analysis.get('behavior', {}).get('posting_frequency', 'Unknown'),
        "content_themes": analysis.get('content_themes') or 'Unknown',
        "layer_1_sentiment_ideology": {
            "scores": {
                "pos": safe_float(layer_1_scores.get('pos') if isinstance(layer_1_scores, dict) else 0, 0.0),
                "neg": safe_float(layer_1_scores.get('neg') if isinstance(layer_1_scores, dict) else 0, 0.0),
                "neu": safe_float(layer_1_scores.get('neu') if isinstance(layer_1_scores, dict) else 0, 0.0)
            },
            "ideology": layer_1.get('ideology') or analysis.get('ideology_details', {}).get('primary_ideology') or analysis.get('ideology') or 'Centrist',
            "affect": layer_1.get('affect') or analysis.get('affect') or 'Neutral',
            "signals": {
                "outrage": safe_int(layer_1.get('signals', {}).get('outrage') if isinstance(layer_1.get('signals', {}), dict) else analysis.get('signals', {}).get('outrage') if isinstance(analysis.get('signals', {}), dict) else 0, 0),
                "fear": safe_int(layer_1.get('signals', {}).get('fear') if isinstance(layer_1.get('signals', {}), dict) else analysis.get('signals', {}).get('fear') if isinstance(analysis.get('signals', {}), dict) else 0, 0),
                "hope": safe_int(layer_1.get('signals', {}).get('hope') if isinstance(layer_1.get('signals', {}), dict) else analysis.get('signals', {}).get('hope') if isinstance(analysis.get('signals', {}), dict) else 0, 0)
            }
        },
        "layer_2_narrative_stance": {
            "framing": layer_2.get('framing') or analysis.get('framing') or 'Unknown',
            "stance": layer_2.get('stance') or analysis.get('stance') or analysis.get('entity_stance') or 'Unknown',
            "us_vs_them": layer_2.get('us_vs_them') or analysis.get('polarization') or analysis.get('us_vs_them') or 'Unknown'
        },
        "layer_3_behavioral_analysis": {
            "account_signals": layer_3.get('account_signals') or analysis.get('behavioral_analysis', {}).get('account_signals') or analysis.get('behavioral_analysis', {}).get('activity_summary') or 'Unknown',
            "karma_velocity": layer_3.get('karma_velocity') or analysis.get('behavioral_analysis', {}).get('karma_velocity') or 'Unknown',
            "burst_posting": layer_3.get('burst_posting') or analysis.get('behavioral_analysis', {}).get('burst_posting') or 'Unknown',
            "dormancy_patterns": layer_3.get('dormancy_patterns') or analysis.get('behavioral_analysis', {}).get('dormancy_patterns') or 'Unknown',
            "temporal": layer_3.get('temporal') or analysis.get('behavioral_analysis', {}).get('temporal') or 'Unknown',
            "coordinated_timing": layer_3.get('coordinated_timing') or analysis.get('behavioral_analysis', {}).get('coordinated_timing') or 'Unknown',
            "event_linked_spikes": layer_3.get('event_linked_spikes') or analysis.get('behavioral_analysis', {}).get('event_linked_spikes') or 'Unknown',
            "content_patterns": layer_3.get('content_patterns') or analysis.get('behavioral_analysis', {}).get('content_patterns') or 'Unknown',
            "copy_paste_ratio": layer_3.get('copy_paste_ratio') or analysis.get('behavioral_analysis', {}).get('copy_paste_ratio') or 'Unknown',
            "lexical_diversity_score": safe_int(layer_3.get('lexical_diversity_score') or analysis.get('behavioral_analysis', {}).get('lexical_diversity') or analysis.get('behavioral_analysis', {}).get('lexical_diversity_score') or 0, 0),
            "edit_frequency": layer_3.get('edit_frequency') or analysis.get('behavioral_analysis', {}).get('edit_frequency') or 'Unknown',
            "reply_speed_under_60s": layer_3.get('reply_speed_under_60s') or analysis.get('behavioral_analysis', {}).get('reply_speed_under_60s') or 'Unknown',
            "same_subreddit_loops": layer_3.get('same_subreddit_loops') or analysis.get('behavioral_analysis', {}).get('subreddit_loops') or 'Unknown',
            "link_domain_bias": layer_3.get('link_domain_bias') or analysis.get('behavioral_analysis', {}).get('link_domain_bias') or 'Unknown',
            "bot_indicators": bot_indicators
        },
        "layer_4_network_structure_sna": {
            "influence": layer_4.get('influence') or analysis.get('network_analysis', {}).get('influence') or 'Unknown',
            "cascade": layer_4.get('cascade') or analysis.get('network_analysis', {}).get('cascade_depth') or 'Unknown',
            "metrics": {
                "betweenness": safe_float(layer_4.get('metrics', {}).get('betweenness') if isinstance(layer_4.get('metrics', {}), dict) else analysis.get('network_analysis', {}).get('betweenness') or 0, 0.0),
                "clustering": safe_float(layer_4.get('metrics', {}).get('clustering') if isinstance(layer_4.get('metrics', {}), dict) else analysis.get('network_analysis', {}).get('clustering') or 0, 0.0)
            },
            "community_detect": layer_4.get('community_detect') or analysis.get('network_analysis', {}).get('community_count') or 'Unknown',
            "bridge_node_id": layer_4.get('bridge_node_id') or analysis.get('network_analysis', {}).get('bridge_nodes') or 'Unknown',
            "amplifier_accounts": layer_4.get('amplifier_accounts') or analysis.get('network_analysis', {}).get('amplifier_accounts') or [],
            "cross_sub_migration_flow_vectors": layer_4.get('cross_sub_migration_flow_vectors') or analysis.get('network_analysis', {}).get('migration_flows') or 'Unknown'
        },
        "layer_5_threat_political_status": {
            "threat_level": threat_level,
            "threat_score": threat_score,
            "narratives": visibility_narratives or 'No threat narratives identified.',
            "interference": interference or 'No signals detected.',
            "protest": protest or 'No tactical coordination found.',
            "foreign_actor_fingerprints": foreign_actor_fingerprints or 'Unknown',
            "mnc_institutional_brand_reputation_shifts": brand_shifts or 'Unknown',
            "employee_sentiment_leak": employee_leak or 'Unknown',
            "coordinated_corp_attack": coordinated_attack or 'No',
            "policy_pressure_campaigns": policy_pressure_campaigns or 'No',
            "political_status": political_status or 'Unknown',
            "party_sentiment_delta": party_delta,
            "topic_salience_ranking": layer_5.get('topic_salience_ranking') or analysis.get('topic_salience_ranking') or [],
            "astroturf_confidence_score": astroturf_confidence_score,
            "crisis_escalation_index": crisis_escalation_index
        },
        "sentiment": analysis.get('sentiment', {}),
        "ideology": {
            "primary_ideology": analysis.get('ideology_details', {}).get('primary_ideology') or analysis.get('ideology') or 'Centrist',
            "confidence": safe_float(analysis.get('ideology_details', {}).get('confidence') or 0.5, 0.5),
            "indicators": analysis.get('ideology_details', {}).get('indicators') or [],
            "description": analysis.get('ideology_details', {}).get('description') or 'Moderate centrist views',
            "scores": analysis.get('ideology_details', {}).get('scores') or {}
        },
        "score": {
            "influence": safe_int(scores.get('influence'), 0),
            "trust": safe_int(scores.get('trust'), 0),
            "activity": safe_int(scores.get('activity'), 0),
            "engagement": safe_int(scores.get('engagement'), 0),
            "overall": safe_int(scores.get('overall'), 0)
        },
        "red_flags": analysis.get('red_flags', ''),
        "assessment": analysis.get('assessment') or analysis.get('summary') or 'No assessment available',
        "raw_output": analysis.get('raw_output')
    }


def compute_sentiment_vader(texts):
    if not sia or not texts:
        # Basic fallback sentiment analysis when VADER is not available
        combined_text = " ".join(texts[:50]).lower()
        pos_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic', 'love', 'like', 'best', 'awesome']
        neg_words = ['bad', 'terrible', 'awful', 'hate', 'worst', 'horrible', 'stupid', 'dumb', 'suck', 'fail']
        
        pos_count = sum(1 for word in pos_words if word in combined_text)
        neg_count = sum(1 for word in neg_words if word in combined_text)
        total_words = len(combined_text.split())
        
        if total_words == 0:
            compound = 0
        else:
            compound = (pos_count - neg_count) / max(total_words, 10)  # Normalize
            compound = max(-1, min(1, compound))  # Clamp to [-1, 1]
        
        pos_score = pos_count / max(total_words, 1)
        neg_score = neg_count / max(total_words, 1)
        neu_score = 1 - pos_score - neg_score
        
        overall = "positive" if compound > 0.05 else "negative" if compound < -0.05 else "neutral"
        
        return {
            "vader_compound": round(compound, 3),
            "vader_pos": round(pos_score, 3),
            "vader_neg": round(neg_score, 3),
            "vader_neu": round(neu_score, 3),
            "overall": overall
        }
    
    combined_text = " ".join(texts[:50])  # Limit to first 50 posts
    scores = sia.polarity_scores(combined_text)
    overall = "positive" if scores['compound'] > 0.05 else "negative" if scores['compound'] < -0.05 else "neutral"
    return {
        "vader_compound": round(scores['compound'], 3),
        "vader_pos": round(scores['pos'], 3),
        "vader_neg": round(scores['neg'], 3),
        "vader_neu": round(scores['neu'], 3),
        "overall": overall
    }


def compute_toxicity_basic(texts):
    if not texts:
        return {"score": 0, "level": "low", "details": "No text provided"}
    toxic_keywords = ["attack", "kill", "bomb", "hate", "violence", "threat"]
    combined_text = " ".join(texts).lower()
    matches = [w for w in toxic_keywords if w in combined_text]
    score = min(1.0, len(matches) * 0.2)
    level = "high" if score > 0.7 else "medium" if score > 0.3 else "low"
    return {"score": round(score, 3), "level": level, "details": f"Keyword matches: {', '.join(matches)}" if matches else "No toxic keywords found"}


def compute_topics_basic(texts):
    if not texts:
        return {"top_topics": [], "tfidf_keywords": []}
    words = re.findall(r'\w+', " ".join(texts[:50]).lower())
    stop_words = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "with", "is", "are", "was", "were"}
    filtered_words = [w for w in words if len(w) > 3 and w not in stop_words]
    top_words = [word for word, count in Counter(filtered_words).most_common(10)]
    return {"top_topics": top_words[:5], "tfidf_keywords": top_words[5:]}


def compute_ideology_basic(texts, profile=None):
    """Analyze texts and profile for ideological classification using Hugging Face AI."""
    if not texts:
        return {
            "primary_ideology": "Centrist",
            "confidence": 0.5,
            "indicators": [],
            "description": "Insufficient data for ideology classification",
            "scores": {}
        }
    
    # Prepare text for analysis
    # Use better sampling: take first 20 posts but keep more characters for nuance
    sample_text = "\n".join([f"- {t[:400]}" for t in texts[:20]])
    profile_info = f"Bio/Context: {profile.get('description', '')}" if profile else ""
    full_target_text = f"{profile_info}\n\nRecent Samples:\n{sample_text}"
    
    # Use Hugging Face if API key is available
    if HF_TOKEN:
        try:
            prompt = f"""<s>[INST] Analyze the comprehensive worldview and ideology of this Reddit user. 
            Do not provide a generic 'Centrist' or 'Neutral' label unless the data explicitly supports it.
            Look for subtle philosophical, economic, lifestyle, or technological markers (e.g. FIRE, Transhumanism, Nihilism, Techno-optimism, Libertarianism, etc.).
            
            USER DATA:
            {full_target_text[:2500]}
            
            Return ONLY a valid JSON object with the following keys:
            - primary_ideology: (string) The specific identified worldview.
            - confidence: (float 0-1) How certain the analysis is.
            - indicators: (array of strings) 3-5 specific linguistic or conceptual markers found in the text.
            - description: (string) A concise 2-sentence explanation of this worldview in the user's context.
            [/INST]</s>"""

            response = requests.post(
                HF_URL,
                headers=HEADERS,
                json={
                    "inputs": prompt,
                    "parameters": {"max_new_tokens": 600, "temperature": 0.2, "return_full_text": False}
                },
                timeout=40
            )

            if response.status_code == 200:
                result = response.json()
                # Handle different HF response formats (generation vs classification)
                if isinstance(result, list) and len(result) > 0:
                    ai_text = result[0].get('generated_text', '')
                else:
                    ai_text = str(result)
                
                # Extract and parse JSON
                ai_data = extract_json_payload(ai_text)
                if ai_data:
                    return {
                        "primary_ideology": ai_data.get("primary_ideology", "Unknown"),
                        "confidence": round(float(ai_data.get("confidence", 0.5)), 2),
                        "indicators": ai_data.get("indicators", []),
                        "description": ai_data.get("description", "AI analysis completed."),
                        "scores": {} # Raw scores not applicable for prompt-based
                    }
        except Exception as e:
            logger.error(f"HF Ideology Analysis Error: {e}")

    # Fallback if HF fails or no key
    # Very basic keywords just to not return empty
    combined_text = full_target_text.lower()
    if any(w in combined_text for w in ["liberal", "progressive", "leftist", "democrat"]):
        primary = "Liberal/Progressive"
    elif any(w in combined_text for w in ["conservative", "republican", "traditional", "right-wing"]):
        primary = "Conservative/Traditional"
    else:
        primary = "Neutral / Unidentified"

    return {
        "primary_ideology": primary,
        "confidence": 0.4,
        "indicators": ["Basic keyword fallback used"],
        "description": "AI analysis unavailable, using basic keyword inference.",
        "scores": {}
    }


def build_reddit_analysis_prompt(profile, posts, target, search_type):
    sample_lines = []
    for idx, post in enumerate(posts[:40], start=1):
        title = post.get("title", "") or "(no title)"
        text = post.get("selftext", "") or post.get("body", "") or ""
        subreddit = post.get("subreddit", "unknown")
        score = post.get("score", 0)
        comments = post.get("num_comments", 0)
        created_utc = post.get("created_utc", 0)
        created_str = datetime.fromtimestamp(created_utc, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if created_utc else "unknown"
        sample_lines.append(
            f"{idx}. {created_str} subreddit={subreddit} score={score} comments={comments} title={title} text={text[:300].replace('\n', ' ')}"
        )

    profile_summary = json.dumps({
        "username": profile.get("username", target),
        "display_name": profile.get("name", target),
        "description": profile.get("description", ""),
        "subscribers": profile.get("subscribers", 0),
        "link_karma": profile.get("link_karma", 0),
        "comment_karma": profile.get("comment_karma", 0),
        "created_utc": profile.get("created_utc", 0),
        "source_count": len(set(post.get("source", "unknown") for post in posts)),
    }, ensure_ascii=False, indent=2)

    prompt = f"""You are an OSINT analyst specializing in Reddit intelligence.
Analyze the following {search_type} data for target {target}.

PROFILE:
{profile_summary}

POST SAMPLES:
"""
    if sample_lines:
        prompt += "\n".join(sample_lines)
    else:
        prompt += "No posts available."

    prompt += """

Analyze the data for advanced OSINT insights:
- Sentiment: Use VADER-like analysis for overall sentiment.
- Toxicity: Assess toxicity levels based on language.
- Topics: Extract main topics and keywords.
- Timeline Analysis: Detect mood shifts over time (e.g., becoming more aggressive).
- Network Graph: Identify interactions, clusters, echo chambers from post patterns.
- Persona Modeling: Build interests, political leaning (probabilistic), risk level.
- Alert System: Trigger alerts for toxicity spikes or keywords like "attack", "kill".

Provide a detailed analysis in strict JSON only. Do not include any prose outside the JSON object.
Return exactly a JSON object with these fields:
{
  "demographics": {"age": "", "gender": "", "location": "", "timezone": ""},
  "ideology": "",
  "affect": "",
  "framing": "",
  "entity_stance": "",
  "polarization": "",
  "behavioral_analysis": {
    "estimated_age": "",
    "activity_summary": "",
    "karma_velocity": "",
    "burst_posting": "",
    "dormancy_patterns": "",
    "temporal": "",
    "coordinated_timing": "",
    "event_linked_spikes": "",
    "copy_paste_ratio": "",
    "lexical_diversity": "",
    "edit_frequency": "",
    "reply_speed": "",
    "subreddit_loops": "",
    "link_domain_bias": "",
    "automation_probability": 0
  },
  "network_analysis": {
    "influence": "",
    "cascade_depth": "",
    "migration_flows": "",
    "betweenness": 0,
    "clustering": 0,
    "community_count": 0,
    "bridge_nodes": ""
  },
  "threat_analysis": {
    "national_threat_level": "",
    "governance_targeting": "",
    "election_interference": "",
    "protest_mobilisation": "",
    "foreign_actor_fp": "",
    "brand_shifts": "",
    "employee_leaks": "",
    "coordinated_attack": "",
    "pressure_campaigns": "",
    "political_status": "",
    "party_delta": 0,
    "astroturf_confidence": 0,
    "crisis_escalation_index": 0
  },
  "personality": {"mbti": "", "bigFive": {"openness": 0, "conscientiousness": 0, "extraversion": 0, "agreeableness": 0, "neuroticism": 0}, "summary": ""},
  "sentiment": {"vader_compound": 0, "vader_pos": 0, "vader_neg": 0, "vader_neu": 0, "overall": ""},
  "toxicity": {"score": 0, "level": "", "details": ""},
  "topics": {"top_topics": [], "tfidf_keywords": []},
  "timeline_analysis": {"mood_shifts": "", "activity_trends": ""},
  "network_graph": {"interactions": [], "clusters": [], "echo_chambers": ""},
  "persona_modeling": {"interests": [], "political_leaning": {"probabilistic": 0, "leaning": ""}, "risk_level": ""},
  "alert_system": {"toxicity_spike": false, "keyword_alerts": [], "triggers": []},
  "confidence": "",
  "summary": ""
}
"""
    return prompt


def calculate_threat_tier(score):
    if score >= 90:
        return "ACTIVE"
    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MED"
    return "LOW"


@app.route("/api/twitter/analyze")

def twitter_analyze():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "Username is required"}), 400
    username = username.strip().lstrip("@")
    try:
        u_url = f"https://api.twitter.com/2/users/by/username/{username}?user.fields=created_at,description,location,name,pinned_tweet_id,profile_image_url,protected,public_metrics,url,username,verified"
        u_resp = requests.get(u_url, headers=get_twitter_bearer_headers(), timeout=15)
        if u_resp.status_code != 200:
            return jsonify({"error": f"Twitter API Error: {u_resp.status_code} - {u_resp.text}"}), u_resp.status_code
        user_data = u_resp.json().get("data")
        if not user_data:
            return jsonify({"error": "User not found"}), 404
        user_id = user_data["id"]
        t_url = f"https://api.twitter.com/2/users/{user_id}/tweets"
        t_resp = requests.get(t_url, headers=get_twitter_bearer_headers(), params={"max_results": 100, "tweet.fields": "created_at,public_metrics,entities,context_annotations,geo", "expansions": "geo.place_id"}, timeout=15)
        if t_resp.status_code != 200:
            return jsonify({"error": f"Twitter API Error (Tweets): {t_resp.status_code} - {t_resp.text}"}), t_resp.status_code
        tweets_data = t_resp.json().get("data", [])
        data_dir = os.path.join(app.root_path, "data")
        os.makedirs(data_dir, exist_ok=True)
        with open(os.path.join(data_dir, f"twitter_data_{username}.json"), "w") as f:
            json.dump({"username": username, "profile": user_data, "tweets": tweets_data}, f, indent=2)
        return jsonify({"status": "success", "data": user_data, "tweets": tweets_data})
    except Exception as e:
        logger.exception("Twitter OSINT Error")
        return jsonify({"error": str(e)}), 500


@app.route("/api/twitter/logout")
def twitter_logout():
    return jsonify({"status": "success"})


@app.route("/api/twitter/ai_analyze", methods=["POST"])

def twitter_ai_analyze():
    data = request.json or {}
    username = data.get("username", "")
    engine = (data.get("engine", "huggingface") or "huggingface").lower()
    if not username:
        return jsonify({"error": "Username is required"}), 400
    data_path = os.path.join(app.root_path, "data", f"twitter_data_{username}.json")
    if not os.path.exists(data_path):
        return jsonify({"error": "No data found for analysis"}), 400
    with open(data_path, "r") as f:
        stored_data = json.load(f)
    tweets = stored_data.get("tweets", [])
    if not tweets:
        return jsonify({"error": "No tweets for analysis"}), 400
    tweet_text = "\n".join([f"- {t.get('text', '')}" for t in tweets[:30]])
    prompt = f"Analyze the following tweets for user @{username}:\n{tweet_text}"
    try:
        # Basic Local Analysis instead of OpenAI
        tweet_count = len(tweets)
        avg_retweets = sum(t.get("public_metrics", {}).get("retweet_count", 0) for t in tweets) / tweet_count if tweet_count else 0
        ai_data = json.dumps({
            "summary": f"Basic analysis for {username}: Total {tweet_count} tweets, avg {avg_retweets:.1f} retweets.",
            "metrics": {"total_tweets": tweet_count, "avg_engagement": avg_retweets}
        })
        parsed_json = json.loads(ai_data)
        return jsonify({"status": "success", "ai_report": parsed_json, "engine_used": "basic_local"})
    except Exception as e:
        logger.exception("AI Analytic Error")
        return jsonify({"error": str(e)}), 500


@app.route("/api/twitter/connections")

def twitter_connections():
    user_id = request.args.get("id")
    ctype = request.args.get("type", "followers")
    if not user_id:
        return jsonify({"error": "User ID is required"}), 400
    if user_id == "123456789":
        return jsonify({"status": "success", "data": [{"id": "mock_id_1", "username": "connected_user_1"}, {"id": "mock_id_2", "username": "connected_user_2"}]})
    try:
        resp = requests.get(f"https://api.twitter.com/2/users/{user_id}/{ctype}", headers=get_twitter_bearer_headers(), timeout=15)
        if resp.status_code != 200:
            return jsonify(resp.json()), resp.status_code
        return jsonify({"status": "success", "data": resp.json().get("data", [])})
    except Exception as e:
        logger.exception("Connections Fetch Error")
        return jsonify({"error": str(e)}), 500


@app.route("/api/twitter/search_advanced")

def twitter_search_advanced():
    query_text = request.args.get("query", "").strip()
    handle = request.args.get("handle", "").strip().lstrip("@")
    location = request.args.get("location", "").strip()
    category = request.args.get("category", "all")
    parts = []
    if query_text:
        parts.append(query_text)
    if handle:
        parts.append(f"from:{handle}")
    if location:
        parts.append(location)
    if category == "media":
        parts.append("has:media")
    elif category == "links":
        parts.append("has:links")
    elif category == "high_engagement":
        parts.append("min_faves:50")
    full_query = " ".join(parts) or "news"
    try:
        resp = requests.get(
            "https://api.twitter.com/2/tweets/search/recent",
            headers=get_twitter_bearer_headers(),
            params={"query": full_query, "max_results": 100, "tweet.fields": "created_at,public_metrics,entities,geo"},
            timeout=15,
        )
        if resp.status_code != 200:
            return jsonify(resp.json()), resp.status_code
        return jsonify({"status": "success", "tweets": resp.json().get("data", []), "includes": resp.json().get("includes", {})})
    except Exception as e:
        logger.exception("Global Search Error")
        return jsonify({"error": str(e)}), 500


def normalize_reddit_post(post):
    normalized = dict(post)
    normalized['score'] = int(post.get('score') or post.get('ups') or post.get('upvotes') or 0)
    normalized['num_comments'] = int(post.get('num_comments') or post.get('comments') or post.get('comment_count') or 0)
    subreddit_raw = post.get('subreddit') or post.get('subreddit_name_prefixed') or post.get('subreddit_name') or ''
    normalized['subreddit'] = str(subreddit_raw).replace('r/', '').replace('/r/', '').strip()
    normalized['author'] = post.get('author') or post.get('author_name') or post.get('author_fullname') or post.get('user') or 'unknown'
    normalized['title'] = post.get('title') or post.get('headline') or post.get('link_title') or ''
    normalized['selftext'] = post.get('selftext') or post.get('body') or post.get('text') or ''
    created = post.get('created_utc') or post.get('created') or post.get('created_at') or 0
    if isinstance(created, str):
        try:
            created = float(created)
        except Exception:
            created = 0
    if isinstance(created, (int, float)) and created > 1e10:
        created = int(created / 1000)
    normalized['created_utc'] = int(created or 0)
    return normalized

def extract_json_payload(text):
    if not text:
        return None

    cleaned = re.sub(r'```json|```', '', text).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    start = None
    depth = 0
    in_string = False
    escape = False
    for idx, char in enumerate(cleaned):
        if char == '"' and not escape:
            in_string = not in_string
        if char == '\\' and not escape:
            escape = True
            continue
        escape = False
        if in_string:
            continue
        if char == '{':
            if start is None:
                start = idx
            depth += 1
        elif char == '}':
            if start is not None:
                depth -= 1
                if depth == 0:
                    fragment = cleaned[start:idx + 1]
                    try:
                        return json.loads(fragment)
                    except json.JSONDecodeError:
                        start = None
    return None


def normalize_reddit_analysis(analysis):
    if not isinstance(analysis, dict):
        return {}

    demographics = analysis.get('demographics', {})
    personality = analysis.get('personality', {})
    big_five = personality.get('big_five', {}) if isinstance(personality.get('big_five', {}), dict) else {}
    scores = analysis.get('score') or analysis.get('scores') or {}
    occupation_indicators = analysis.get('occupation_indicators') or analysis.get('occupation', {}).get('keywords') or []
    if isinstance(occupation_indicators, str):
        occupation_indicators = [occupation_indicators]

    return {
        "demographics": {
            "age_estimate": demographics.get('age_estimate', demographics.get('age', 'Unknown')),
            "gender": demographics.get('gender', 'Unknown'),
            "location": demographics.get('location', 'Unknown'),
            "language": demographics.get('language', 'Unknown'),
            "timezone": demographics.get('timezone', 'Unknown')
        },
        "occupation_indicators": occupation_indicators,
        "interests": analysis.get('interests', []),
        "personality": {
            "mbti": personality.get('mbti') or personality.get('mbti_type') or 'Unknown',
            "big_five": {
                "openness": int(big_five.get('openness', 0) or 0),
                "conscientiousness": int(big_five.get('conscientiousness', 0) or 0),
                "extraversion": int(big_five.get('extraversion', 0) or 0),
                "agreeableness": int(big_five.get('agreeableness', 0) or 0),
                "neuroticism": int(big_five.get('neuroticism', 0) or 0)
            }
        },
        "behavioral_patterns": analysis.get('behavioral_patterns') or analysis.get('behavior', {}).get('posting_frequency', 'Unknown'),
        "content_themes": analysis.get('content_themes') or 'Unknown',
        # New Intelligence Layers
        "layer_1_sentiment_ideology": analysis.get('layer_1_sentiment_ideology', {}),
        "layer_2_narrative_stance": analysis.get('layer_2_narrative_stance', {}),
        "layer_3_behavioral_analysis": analysis.get('layer_3_behavioral_analysis', {}),
        "layer_4_network_structure_sna": analysis.get('layer_4_network_structure_sna', {}),
        "layer_5_threat_political_status": analysis.get('layer_5_threat_political_status', {}),
        "sentiment": analysis.get('sentiment', {}),
        "score": {
            "influence": int(scores.get('influence', 0) or 0),
            "trust": int(scores.get('trust', 0) or 0),
            "activity": int(scores.get('activity', 0) or 0),
            "engagement": int(scores.get('engagement', 0) or 0),
            "overall": int(scores.get('overall', 0) or 0)
        },
        "red_flags": analysis.get('red_flags', ''),
        "assessment": analysis.get('assessment') or analysis.get('summary') or 'No assessment available',
        "raw_output": analysis.get('raw_output')
    }

@app.route('/api/reddit/search/author/<username>')

def reddit_search_author(username):
    """Search Reddit posts by author using Native API."""
    limit = int(request.args.get('limit', 100))
    posts = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    
    profile = {
        "username": username,
        "name": username,
        "description": f"Reddit user profile for {username}"
    }

    try:
        # Fetch profile
        about_url = f"https://www.reddit.com/user/{username}/about.json"
        about_resp = requests.get(about_url, headers=headers, timeout=10)
        if about_resp.status_code == 200:
            about_data = about_resp.json().get('data', {})
            profile.update({
                "subscribers": about_data.get('subreddit', {}).get('subscribers', 0),
                "title": about_data.get('subreddit', {}).get('title', ''),
                "public_description": about_data.get('subreddit', {}).get('public_description', ''),
                "created_utc": about_data.get('created_utc', 0),
                "link_karma": about_data.get('link_karma', 0),
                "comment_karma": about_data.get('comment_karma', 0),
                "icon_img": about_data.get('icon_img', '')
            })
            profile["description"] = profile.get("public_description") or profile["description"]

        # Fetch posts
        posts_url = f"https://www.reddit.com/user/{username}.json?limit={limit}"
        posts_resp = requests.get(posts_url, headers=headers, timeout=10)
        if posts_resp.status_code == 200:
            posts_data = posts_resp.json().get('data', {}).get('children', [])
            for child in posts_data:
                post = child.get('data', {})
                normalized = normalize_reddit_post(post)
                normalized['source'] = 'reddit-native'
                # Handle comment vs post
                if 'body' in post:
                    normalized['selftext'] = post.get('body')
                    normalized['title'] = f"Comment on: {post.get('link_title', '')}"
                posts.append(normalized)
    except Exception as e:
        print(f"Reddit Native API Error: {e}")

    # Remove duplicates based on post ID if available
    seen_ids = set()
    unique_posts = []
    for post in posts:
        post_id = post.get('id') or post.get('post_id')
        if post_id and post_id not in seen_ids:
            seen_ids.add(post_id)
            unique_posts.append(post)

    unique_posts.sort(key=lambda x: x.get('created_utc', 0), reverse=True)
    unique_posts = unique_posts[:limit]

    # Save to JSON
    data_filename = f"reddit_data_{username}.json"
    data_path = os.path.join(app.root_path, 'data', data_filename)
    with open(data_path, 'w') as f:
        json.dump({
            "username": username,
            "profile": profile,
            "posts": unique_posts
        }, f, indent=2)

    return jsonify({
        "status": "success",
        "profile": profile,
        "posts": unique_posts
    })

@app.route('/api/reddit/search/subreddit/<subreddit>')

def reddit_search_subreddit(subreddit):
    """Search Reddit posts by subreddit using Native API."""
    limit = int(request.args.get('limit', 100))
    posts = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    
    profile = {
        "name": subreddit,
        "display_name": f"r/{subreddit}",
        "description": f"Subreddit {subreddit}"
    }

    try:
        # Fetch about
        about_url = f"https://www.reddit.com/r/{subreddit}/about.json"
        about_resp = requests.get(about_url, headers=headers, timeout=10)
        if about_resp.status_code == 200:
            about_data = about_resp.json().get('data', {})
            profile.update({
                "subscribers": about_data.get('subscribers', 0),
                "title": about_data.get('title', ''),
                "public_description": about_data.get('public_description', ''),
                "created_utc": about_data.get('created_utc', 0),
                "icon_img": about_data.get('icon_img', '')
            })
            profile["description"] = profile.get("public_description") or profile["description"]

        # Fetch posts
        posts_url = f"https://www.reddit.com/r/{subreddit}.json?limit={limit}"
        posts_resp = requests.get(posts_url, headers=headers, timeout=10)
        if posts_resp.status_code == 200:
            posts_data = posts_resp.json().get('data', {}).get('children', [])
            for child in posts_data:
                post = child.get('data', {})
                normalized = normalize_reddit_post(post)
                normalized['source'] = 'reddit-native'
                posts.append(normalized)
    except Exception as e:
        print(f"Reddit Native API Error: {e}")

    # Save to JSON
    data_filename = f"reddit_data_r_{subreddit}.json"
    data_path = os.path.join(app.root_path, 'data', data_filename)
    with open(data_path, 'w') as f:
        json.dump({
            "subreddit": subreddit,
            "profile": profile,
            "posts": posts
        }, f, indent=2)

    return jsonify({
        "status": "success",
        "profile": profile,
        "posts": posts
    })

@app.route('/api/reddit/ai_analyze', methods=['POST'])

def reddit_ai_analyze():
    """Analyze Reddit posts using AI to generate behavioral and sentiment insights."""
    data = request.json or {}
    target = data.get('target', '')
    search_type = data.get('search_type', 'user')
    engine = (data.get('engine', 'huggingface') or 'huggingface').lower()
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    # Load data from JSON
    if search_type == 'user':
        data_filename = f"reddit_data_{target}.json"
    else:
        data_filename = f"reddit_data_r_{target}.json"
    
    data_path = os.path.join(app.root_path, 'data', data_filename)
    if not os.path.exists(data_path):
        return jsonify({"error": "No data found for analysis"}), 400
    
    with open(data_path, 'r') as f:
        stored_data = json.load(f)
    
    posts = stored_data.get('posts', [])
    profile = stored_data.get('profile', {})
    
    if not posts:
        return jsonify({"error": "No posts for analysis"}), 400
    
    # Prepare content for AI
    post_content = "\n".join([f"- {p.get('title', '')}: {p.get('selftext', '')[:200]}" for p in posts[:30]])
    profile_summary = json.dumps({
        "username": profile.get('username', target),
        "name": profile.get('name', ''),
        "description": profile.get('description', ''),
        "subscribers": profile.get('subscribers', 0),
        "additional_fields": {k: v for k, v in profile.items() if k not in ['username', 'name', 'description', 'subscribers']}
    }, ensure_ascii=False)

    if search_type == 'user':
        prompt = f"""You are a senior OSINT Intelligence Analyst. Conduct a high-fidelity 'Layered Intelligence' analysis on this Reddit user.

PROFILE DATA:
{profile_summary}

POST SAMPLES:
{post_content}

Your goal is to provide a comprehensive 5-layer intelligence report identifying deep behavioral, sentimental, and network traits. Extrapolate cautiously where direct data is scarce.

RESPOND ONLY WITH VALID JSON IN THE EXACT STRUCTURE BELOW:
{{
  "demographics": {{ "age": "", "gender": "", "location": "", "timezone": "" }},
  "occupation_indicators": [],
  "interests": [ {{ "topic": "Interest Name", "reason": "Reason for assigning this interest" }} ],
  "personality": {{ "mbti": "", "big_five": {{ "openness": 0, "conscientiousness": 0, "extraversion": 0, "agreeableness": 0, "neuroticism": 0 }} }},
  "layer_1_sentiment_ideology": {{
    "scores": {{ "pos": 0.0, "neg": 0.0, "neu": 0.0 }},
    "ideology": "Ideological lean",
    "affect": "Political affect (e.g. Hostile, Neutral)",
    "signals": {{ "outrage": 0, "fear": 0, "hope": 0 }}
  }},
  "layer_2_narrative_stance": {{
    "framing": "How the user frames topics",
    "stance": "Entity-level stance (Pro/Con/Neutral)",
    "us_vs_them": "Presence of us-vs-them rhetoric"
  }},
  "layer_3_behavioral_analysis": {{
    "account_signals": "Age vs activity correlation",
    "karma_velocity": "High/Low",
    "burst_posting": "Yes/No",
    "dormancy_patterns": "Describe dormancy",
    "temporal": "Post time heatmap / timezone inference",
    "coordinated_timing": "Yes/No",
    "event_linked_spikes": "Yes/No",
    "content_patterns": "Describe patterns",
    "copy_paste_ratio": "0-100%",
    "link_domain_bias": "Describe links",
    "template_language": "Yes/No",
    "lexical_diversity_score": 0,
    "edit_frequency": "High/Low",
    "reply_speed_under_60s": "Yes/No",
    "same_subreddit_loops": "Yes/No",
    "bot_indicators": {{ "score": 0, "flags": [] }}
  }},
  "layer_4_network_structure_sna": {{
    "influence": "Influence flow",
    "cascade": "Cascade depth",
    "metrics": {{ "betweenness": 0.0, "clustering": 0.0 }},
    "community_detect": "Louvain/Infomap",
    "bridge_node_id": "Detected ID",
    "amplifier_accounts": [],
    "cross_sub_migration_flow_vectors": "Describe flows"
  }},
  "layer_5_threat_political_status": {{
    "threat_level": "LOW/ELEVATED/CRITICAL",
    "threat_score": 0,
    "narratives": "Targeting gov/institutions",
    "interference": "Election/Gov interference",
    "protest": "Protest mobilisation",
    "foreign_actor_fingerprints": "Describe",
    "mnc_institutional_brand_reputation_shifts": "Shifts",
    "employee_sentiment_leak": "Yes/No",
    "coordinated_corp_attack": "Yes/No",
    "policy_pressure_campaigns": "Yes/No",
    "political_status": "Status",
    "party_sentiment_delta": 0.0,
    "topic_salience_ranking": [],
    "astroturf_confidence_score": 0,
    "crisis_escalation_index": 0
  }},
  "assessment": "Comprehensive summary",
  "score": {{ "influence": 0, "trust": 0, "activity": 0, "engagement": 0, "overall": 0 }}
}}"""
    else:
        prompt = f"""You are a senior OSINT Intelligence Analyst. Conduct a high-fidelity 'Layered Intelligence' analysis on this Subreddit community.

COMMUNITY DATA:
{profile_summary}

POST SAMPLES:
{post_content}

Analyze specifically for:
Layer 1: Community sentiment delta, ideological lean, collective outrage/hope.
Layer 2: Narrative framing, institutional stance, coordinated rhetoric.
Layer 3: Community posting patterns, temporal spikes, bot/astroturf indicators, karma velocity, bursting.
Layer 4: Network metrics (betweenness, clustering), influence flow, bridge structures.
Layer 5: National threat level, election interference, brand reputation shifts, policy pressure campaigns.

RESPOND ONLY WITH VALID JSON using the same 5-layer structure as defined for user analysis."""


    try:
        if engine == 'openai':
            openai_payload = {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.5,
                "max_tokens": 1900
            }
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json"
                },
                json=openai_payload,
                timeout=30
            )
            response.raise_for_status()
            ai_data = response.json().get('choices', [{}])[0].get('message', {}).get('content', '{}').strip()

        elif engine == 'ollama':
            response = requests.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False
                },
                timeout=120
            )
            response.raise_for_status()
            ai_data = response.json().get('message', {}).get('content', '').strip()

        elif engine == 'huggingface':
            payload = {
                "model": MODEL_ID,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.5,
                "max_tokens": 1900
            }
            response = requests.post(HF_URL, headers=HEADERS, json=payload, timeout=30)
            response.raise_for_status()
            ai_data = response.json().get('choices', [{}])[0].get('message', {}).get('content', '{}').strip()

        else:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "meta-llama/llama-3-8b-instruct",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.5,
                    "max_tokens": 1900
                },
                timeout=30
            )
            response.raise_for_status()
            ai_data = response.json().get('choices', [{}])[0].get('message', {}).get('content', '{}').strip()

        ai_data = ai_data.replace('```json', '').replace('```', '').strip()
        analysis = None
        try:
            analysis = json.loads(ai_data)
        except json.JSONDecodeError:
            analysis = extract_json_payload(ai_data)

        # Save raw AI output for debugging
        debug_filename = f"reddit_ai_debug_{target}_{int(time.time())}.txt"
        debug_path = os.path.join(app.root_path, 'data', debug_filename)
        with open(debug_path, 'w') as f:
            f.write(f"Target: {target}\nSearch Type: {search_type}\nEngine: {engine}\n\nRaw AI Output:\n{ai_data}\n\nParsed Analysis:\n{json.dumps(analysis, indent=2) if analysis else 'None'}")

        if analysis is None:
            analysis = {
                "demographics": {
                    "age_estimate": "Unknown",
                    "gender": "Unknown",
                    "location": "Unknown",
                    "language": "Unknown",
                    "timezone": "Unknown"
                },
                "occupation_indicators": [],
                "interests": [],
                "personality": {
                    "mbti": "Unknown",
                    "big_five": {
                        "openness": 0,
                        "conscientiousness": 0,
                        "extraversion": 0,
                        "agreeableness": 0,
                        "neuroticism": 0
                    }
                },
                "behavioral_patterns": "Unable to extract behavioral patterns from AI output.",
                "content_themes": "Unknown",
                "sentiment": {
                    "overall": "Unknown",
                    "positive_percentage": 0,
                    "negative_percentage": 0,
                    "neutral_percentage": 100,
                    "stability": "Unknown"
                },
                "score": {
                    "influence": 0,
                    "trust": 0,
                    "activity": 0,
                    "engagement": 0,
                    "overall": 0
                },
                "red_flags": "Could not parse AI output.",
                "assessment": "AI output parse failed.",
                "raw_output": ai_data
            }

        analysis = normalize_reddit_analysis(analysis)

        # Save to Database for intelligence tracking
        try:
            conn = get_conn()
            c = conn.cursor()
            c.execute("INSERT INTO reddit_intel (target_name, data_json, search_type) VALUES (?, ?, ?)",
                      (target, json.dumps(analysis), search_type))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"DB Error (reddit_intel): {e}")

        # Send analysis report to Discord Bot
        try:
            threat_level = analysis.get('layer_5_threat_political_status', {}).get('threat_level', 'UNKNOWN')
            threat_score = analysis.get('layer_5_threat_political_status', {}).get('threat_score', 0)
            
            if threat_level and 'bot_manager' in globals():
                # Run async function in new event loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(
                    bot_manager.send_reddit_analysis_report(target, threat_level, threat_score, analysis)
                )
                loop.close()
                logging.info(f"Discord analysis report sent for {target}")
        except Exception as e:
            logging.warning(f"Error sending Discord analysis report: {e}")

        return jsonify({
            "status": "success",
            "analysis": analysis,
            "target": target,
            "search_type": search_type,
            "engine": engine
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- REDDIT MONITORING LOGIC ----------------

def calculate_threat_tier(score):
    if score >= 90: return "ACTIVE"
    if score >= 70: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 30: return "MED"
    return "LOW"

@celery.task
def monitor_reddit_target_task(monitor_id):
    """Celery task to perform a monitoring cycle for a specific target."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT target_name, target_type, webhook_url, threat_tier FROM reddit_monitors WHERE id = ?", (monitor_id,))
    target_data = c.fetchone()
    if not target_data:
        conn.close()
        return "Monitor not found"
    
    target_name, target_type, webhook_url, current_tier = target_data
    
    # In a real implementation, we would call a function to fetch latest reddit data
    # For now, we use a simulation or a simple heuristic based on existing data
    # To properly implement this, we'd need a non-request-bound version of reddit_ai_analyze
    
    # Simulation for Demo/Worker Proof of Concept
    new_score = random.randint(10, 95)
    new_tier = calculate_threat_tier(new_score)
    
    c.execute("UPDATE reddit_monitors SET threat_score = ?, threat_tier = ?, status = 'MONITORING', last_check = CURRENT_TIMESTAMP WHERE id = ?",
              (new_score, new_tier, monitor_id))
    
    # Alerting logic
    if (new_tier != current_tier or new_score > 80) and webhook_url:
        message = f"🚨 **REDDIT OSINT MONITORING ALERT** 🚨\n**Target:** `{target_name}` ({target_type})\n**New Tier:** `{new_tier}`\n**Current Score:** `{new_score}/100`"
        try:
            requests.post(webhook_url, json={"content": message}, timeout=10)
            c.execute("UPDATE reddit_monitors SET last_alert = CURRENT_TIMESTAMP WHERE id = ?", (monitor_id,))
        except Exception as e:
            print(f"Webhook error: {e}")
            
    conn.commit()
    conn.close()
    return f"Completed monitoring for {target_name}: {new_tier}"

@app.route('/api/reddit/monitor/create', methods=['POST'])

def create_reddit_monitor():
    data = request.json or {}
    target = data.get('target')
    target_type = data.get('type', 'user')
    webhook_url = data.get('webhook_url', DISCORD_WEBHOOK_URL)
    
    if not target:
        return jsonify({"error": "Target name required"}), 400
        
    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute("INSERT INTO reddit_monitors (target_name, target_type, webhook_url) VALUES (?, ?, ?)",
                  (target, target_type, webhook_url))
        monitor_id = c.lastrowid
        conn.commit()
        conn.close()
        
        # Send monitor creation notification to Discord Bot
        try:
            if 'bot_manager' in globals():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(
                    bot_manager.send_monitor_created(target, target_type, str(monitor_id))
                )
                loop.close()
                logging.info(f"Discord monitor notification sent for {target}")
        except Exception as e:
            logging.warning(f"Error sending Discord monitor notification: {e}")
        
        # Trigger an initial check in background
        monitor_reddit_target_task.delay(monitor_id)
        
        return jsonify({"status": "success", "monitor_id": monitor_id, "message": f"Monitor established for {target}"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Monitor already established for this target"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/reddit/monitors', methods=['GET'])

def list_reddit_monitors():
    try:
        conn = get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM reddit_monitors ORDER BY last_check DESC")
        monitors = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"status": "success", "monitors": monitors})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@celery.task
def daily_intel_report_task():
    """Aggregates monitoring results into a daily intel report."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT target_name, threat_tier, threat_score FROM reddit_monitors")
    targets = c.fetchall()
    conn.close()
    
    if not targets: return "No targets to report."
    
    report = "📋 **DAILY REDDIT INTELLIGENCE DIGEST** 📋\n"
    report += "--------------------------------------\n"
    for name, tier, score in targets:
        report += f"🔹 **{name}**: Tier `{tier}` (Score: {score}/100)\n"
    
    if DISCORD_WEBHOOK_URL:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": report})
    
    return "Daily report successfully dispatched."

# Discord API Endpoints for sending messages
@app.route('/api/discord/send-webhook', methods=['POST'])

def send_discord_webhook():
    """Send message via Discord webhook from backend"""
    data = request.json or {}
    message = data.get('message', '')
    embed = data.get('embed', None)
    
    if not message and not embed:
        return jsonify({"error": "Message or embed required"}), 400
    
    payload = {"content": message}
    
    # Handle embeds array format
    if embed:
        if isinstance(embed, list):
            payload["embeds"] = embed
        else:
            payload["embeds"] = [embed]
    
    try:
        response = requests.post(
            DISCORD_WEBHOOK_URL,
            json=payload,
            timeout=10
        )
        
        if response.status_code in [200, 204]:
            logging.info("Discord webhook message sent successfully")
            return jsonify({"status": "success", "message": "Message sent to Discord webhook"})
        else:
            error_msg = f"Webhook error: {response.status_code} - {response.text}"
            logging.error(error_msg)
            return jsonify({"status": "error", "error": error_msg}), response.status_code
            
    except Exception as e:
        logging.error(f"Error sending webhook: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route('/api/discord/send-bot', methods=['POST'])

def send_discord_bot_message():
    """Send message via Discord Bot API from backend"""
    data = request.json or {}
    message = data.get('message', '')
    embed = data.get('embed', None)
    
    if not message and not embed:
        return jsonify({"error": "Message or embed required"}), 400
    
    payload = {"content": message}
    
    # Handle embeds array format
    if embed:
        if isinstance(embed, list):
            payload["embeds"] = embed
        else:
            payload["embeds"] = [embed]
    
    try:
        response = requests.post(
            f"https://discord.com/api/v10/channels/YOUR_CHANNNEL_ID/messages",
            headers={
                "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=10
        )
        
        if response.status_code in [200, 201]:
            logging.info("Discord bot message sent successfully")
            return jsonify({"status": "success", "message": "Message sent via bot API"})
        else:
            error_data = response.json() if response.text else {}
            error_msg = f"Bot API error: {response.status_code} - {error_data}"
            logging.error(error_msg)
            return jsonify({"status": "error", "error": error_msg}), response.status_code
            
    except Exception as e:
        logging.error(f"Error sending bot message: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route('/api/discord/send-both', methods=['POST'])

def send_discord_both():
    """Send message via both webhook and bot API"""
    data = request.json or {}
    message = data.get('message', '')
    embed = data.get('embed', None)
    
    if not message and not embed:
        return jsonify({"error": "Message or embed required"}), 400
    
    results = {"webhook": False, "bot": False, "webhook_error": None, "bot_error": None}
    
    payload = {"content": message}
    
    # Handle embeds array format
    if embed:
        if isinstance(embed, list):
            payload["embeds"] = embed
        else:
            payload["embeds"] = [embed]
    
    # Send via webhook
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
        results["webhook"] = response.status_code in [200, 204]
        if not results["webhook"]:
            results["webhook_error"] = f"{response.status_code}: {response.text}"
        logging.info(f"Webhook message: {'Success' if results['webhook'] else f'Failed ({response.status_code})'}")
    except Exception as e:
        results["webhook_error"] = str(e)
        logging.error(f"Webhook error: {e}")
    
    # Send via bot
    try:
        response = requests.post(
            f"https://discord.com/api/v10/channels/YOUR_CHANNEL_ID/messages",
            headers={
                "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=10
        )
        results["bot"] = response.status_code in [200, 201]
        if not results["bot"]:
            results["bot_error"] = f"{response.status_code}: {response.text}"
        logging.info(f"Bot message: {'Success' if results['bot'] else f'Failed ({response.status_code})'}")
    except Exception as e:
        results["bot_error"] = str(e)
        logging.error(f"Bot error: {e}")
    
    if results["webhook"] or results["bot"]:
        methods = []
        if results["webhook"]:
            methods.append("webhook")
        if results["bot"]:
            methods.append("bot")
        
        return jsonify({
            "status": "success",
            "results": results,
            "message": f"Sent via {' and '.join(methods)}"
        })
    else:
        return jsonify({
            "status": "error",
            "error": "Failed to send via both methods",
            "results": results
        }), 500
    
@app.route("/")
def index():
    return render_template("index.html")

# Twitter OSINT Page
@app.route("/social/twitter")

def twitter_osint():
    return render_template("social/twitter.html")


# Reddit OSINT Page
@app.route("/social/reddit")

def reddit_osint():
    return render_template("social/reddit.html")




if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
