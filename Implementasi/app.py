"""
app.py - AI-Assisted Security Analytics Prototype
=================================================
Sistem Deteksi Intrusi Jaringan berbasis Machine Learning (Random Forest)
menggunakan Dataset NSL-KDD.

Dibuat sesuai rancangan menu dari laporan tugas:
  Frontend (4 menu):
    1. Dashboard - Ringkasan status terkini
    2. Prediksi Koneksi - Input manual/CSV untuk deteksi
    3. Riwayat Alert - Log serangan terdeteksi
    4. Evaluasi Model - Confusion matrix & metrik
  Backend (3 menu):
    5. Manajemen Model - Info pipeline aktif
    6. Pengaturan Ambang - Threshold keputusan
    7. Upload Dataset - Upload data baru

Dosen Pengampu: Zuliar Efendi, M.Kom
Kelompok: Handal Karis Arbi & Markus Edison Silalahi
"""

import os
import sys
import json
import uuid
import warnings
import traceback
from datetime import datetime
from io import StringIO

import numpy as np
import pandas as pd
import joblib
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS

from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix, classification_report, accuracy_score,
    precision_score, recall_score, f1_score
)

warnings.filterwarnings('ignore')

# ============================================================
# KONFIGURASI
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(TEMPLATE_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max

# ============================================================
# GLOBAL STATE
# ============================================================
KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]

ATTACK_CATEGORY_MAP = {
    'normal': 'Normal',
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS',
    'smurf': 'DoS', 'teardrop': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS',
    'processtable': 'DoS', 'udpstorm': 'DoS',
    'satan': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L',
    'multihop': 'R2L', 'warezmaster': 'R2L', 'warezclient': 'R2L',
    'spy': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 'snmpguess': 'R2L',
    'snmpgetattack': 'R2L', 'httptunnel': 'R2L', 'sendmail': 'R2L',
    'named': 'R2L', 'worm': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'rootkit': 'U2R',
    'perl': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R',
}

# In-memory state
current_pipeline = None
current_model_info = None
current_threshold = 0.5
alert_history = []
prediction_stats = {
    'total_analyzed': 0,
    'total_attacks': 0,
    'total_normal': 0,
    'attack_categories': {'DoS': 0, 'Probe': 0, 'R2L': 0, 'U2R': 0, 'Unknown Attack': 0}
}


# ============================================================
# MODEL MANAGEMENT
# ============================================================

def train_quick_model():
    """Train a quick model from available data for demo."""
    global current_pipeline, current_model_info
    
    # Find any available data
    data_files = []
    for d in [BASE_DIR, DATA_DIR]:
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith('.csv'):
                    data_files.append(os.path.join(d, f))
    
    if not data_files:
        return False
    
    # Use the largest file
    data_files.sort(key=lambda x: os.path.getsize(x), reverse=True)
    train_file = data_files[0]
    
    print(f"[TRAIN] Using: {train_file}")
    df = pd.read_csv(train_file)
    
    # Find label column
    label_col = None
    for col in ['class', 'label', 'ground_truth_label', 'attack_type', 'target']:
        if col in df.columns:
            label_col = col
            break
    
    if label_col is None:
        return False
    
    # Clean labels
    df[label_col] = df[label_col].astype(str).str.strip().str.lower()
    df['clean_label'] = df[label_col].apply(
        lambda x: x.split('(')[0].strip().rstrip('.') if '(' in str(x) else str(x).strip().rstrip('.')
    )
    df['binary_label'] = df['clean_label'].apply(
        lambda x: 0 if x == 'normal' else 1
    )
    
    # Add log features
    for col in ['duration', 'src_bytes', 'dst_bytes']:
        if col in df.columns:
            df[f'{col}_log1p'] = np.log1p(df[col].astype(float))
    
    # Prepare features
    drop_cols = [label_col, 'binary_label', 'clean_label', 'attack_category']
    if 'difficulty' in df.columns:
        drop_cols.append('difficulty')
    
    feature_cols = [c for c in df.columns if c not in drop_cols and c in KDD_COLUMNS or c.endswith('_log1p')]
    feature_cols = [c for c in feature_cols if c in df.columns]
    
    if not feature_cols:
        feature_cols = [c for c in df.columns if c not in drop_cols]
    
    X = df[feature_cols]
    y = df['binary_label']
    
    cat_cols = [c for c in ['protocol_type', 'service', 'flag'] if c in X.columns]
    num_cols = [c for c in X.columns if c not in cat_cols]
    
    preprocessor = ColumnTransformer([
        ('num', StandardScaler(), num_cols),
        ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), cat_cols)
    ])
    
    pipeline = Pipeline([
        ('preprocess', preprocessor),
        ('clf', RandomForestClassifier(
            n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced'
        ))
    ])
    
    pipeline.fit(X, y)
    
    current_pipeline = pipeline
    current_model_info = {
        'model_name': 'RandomForest_NSL_KDD',
        'algorithm': 'Random Forest Classifier',
        'n_estimators': 100,
        'feature_columns': feature_cols,
        'num_columns': num_cols,
        'cat_columns': cat_cols,
        'n_features': len(feature_cols),
        'trained_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'train_file': train_file,
        'train_samples': len(y),
        'version': '1.0'
    }
    
    # Save
    joblib.dump(pipeline, os.path.join(MODEL_DIR, 'rf_pipeline.pkl'))
    with open(os.path.join(MODEL_DIR, 'model_info.json'), 'w') as f:
        json.dump(current_model_info, f, indent=2)
    
    print(f"[TRAIN] Model trained on {len(y)} samples, {len(feature_cols)} features")
    return True


def load_model():
    """Load model pipeline from file."""
    global current_pipeline, current_model_info
    
    model_path = os.path.join(MODEL_DIR, 'rf_pipeline.pkl')
    info_path = os.path.join(MODEL_DIR, 'model_info.json')
    
    if os.path.exists(model_path):
        try:
            current_pipeline = joblib.load(model_path)
            if os.path.exists(info_path):
                with open(info_path, 'r') as f:
                    current_model_info = json.load(f)
            else:
                current_model_info = {
                    'model_name': 'RandomForest_NSL_KDD',
                    'algorithm': 'Random Forest',
                    'trained_at': 'Unknown',
                    'version': '1.0'
                }
            print("[MODEL] Pipeline loaded successfully")
            return True
        except Exception as e:
            print(f"[MODEL] Error loading: {e}")
    
    # Train new model
    print("[MODEL] No saved model found, training new model...")
    return train_quick_model()


def load_alert_history():
    """Load alert history from file."""
    global alert_history
    
    alert_file = os.path.join(BASE_DIR, 'alert_history.json')
    if os.path.exists(alert_file):
        with open(alert_file, 'r') as f:
            alert_history = json.load(f)
        print(f"[ALERT] Loaded {len(alert_history)} alerts")


def save_alert_history():
    """Save alert history to file."""
    alert_file = os.path.join(BASE_DIR, 'alert_history.json')
    with open(alert_file, 'w') as f:
        json.dump(alert_history, f, indent=2)


def load_threshold():
    """Load threshold from config."""
    global current_threshold
    config_file = os.path.join(BASE_DIR, 'system_config.json')
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
            current_threshold = config.get('decision_threshold', 0.5)
    print(f"[CONFIG] Threshold: {current_threshold}")


def classify_attack(prob, features):
    """Klasifikasi kategori serangan berdasarkan fitur koneksi."""
    flag = str(features.get('flag', '')).upper()
    service = str(features.get('service', '')).lower()
    src_bytes = float(features.get('src_bytes', 0))
    dst_bytes = float(features.get('dst_bytes', 0))
    count = float(features.get('count', 0))
    num_failed = float(features.get('num_failed_logins', 0))
    root_shell = float(features.get('root_shell', 0))
    num_compromised = float(features.get('num_compromised', 0))
    serror_rate = float(features.get('serror_rate', 0))
    rerror_rate = float(features.get('rerror_rate', 0))
    logged_in = float(features.get('logged_in', 0))
    
    # Rule-based kategori (sesuai NSL-KDD taxonomy)
    if flag in ['S0', 'S1', 'S2', 'S3'] and count > 50:
        return 'DoS', 'neptune / smurf / syn-flood', 'High'
    elif flag == 'S0' and serror_rate > 0.5:
        return 'DoS', 'neptune / syn-flood', 'High'
    elif src_bytes > 10000 and count > 100:
        return 'DoS', 'smurf / back', 'High'
    elif root_shell > 0 or num_compromised > 0:
        return 'U2R', 'buffer_overflow / rootkit', 'Critical'
    elif num_failed > 2 and service in ['telnet', 'ftp', 'ssh', 'pop_3', 'imap4']:
        return 'R2L', 'guess_passwd / brute_force', 'High'
    elif logged_in == 0 and service in ['telnet', 'ftp'] and dst_bytes > 500:
        return 'R2L', 'warezclient / phf', 'Medium'
    elif flag == 'REJ' and rerror_rate > 0.5:
        return 'Probe', 'satan / portscan', 'Medium'
    elif count > 100 and flag == 'REJ':
        return 'Probe', 'ipsweep / portsweep', 'Medium'
    elif prob > 0.9:
        return 'DoS', 'unknown high-conf attack', 'High'
    elif prob > 0.7:
        return 'Probe', 'suspicious activity', 'Medium'
    else:
        return 'Unknown', 'low-confidence detection', 'Low'


def predict_connection(features_dict):
    """Prediksi satu koneksi."""
    global prediction_stats
    
    if current_pipeline is None:
        return {'error': 'Model belum dimuat!'}
    
    feature_cols = current_model_info.get('feature_columns', KDD_COLUMNS)
    
    # Build feature row
    row = {}
    for col in feature_cols:
        if col.endswith('_log1p'):
            base_col = col.replace('_log1p', '')
            val = float(features_dict.get(base_col, 0))
            row[col] = np.log1p(val)
        else:
            row[col] = features_dict.get(col, 0)
    
    df_input = pd.DataFrame([row])
    
    # Ensure correct types
    cat_cols = current_model_info.get('cat_columns', ['protocol_type', 'service', 'flag'])
    num_cols = current_model_info.get('num_columns', [])
    
    for c in cat_cols:
        if c in df_input.columns:
            df_input[c] = df_input[c].astype(str)
    for c in num_cols:
        if c in df_input.columns:
            df_input[c] = pd.to_numeric(df_input[c], errors='coerce').fillna(0)
    
    # Predict
    prob = current_pipeline.predict_proba(df_input)[0]
    attack_prob = float(prob[1]) if len(prob) > 1 else float(prob[0])
    is_attack = attack_prob >= current_threshold
    
    # Update stats
    prediction_stats['total_analyzed'] += 1
    if is_attack:
        prediction_stats['total_attacks'] += 1
        category, specific, severity = classify_attack(attack_prob, features_dict)
        prediction_stats['attack_categories'][category] = prediction_stats['attack_categories'].get(category, 0) + 1
    else:
        prediction_stats['total_normal'] += 1
        category, specific, severity = 'Normal', '-', 'None'
    
    result = {
        'prediction': 'Attack' if is_attack else 'Normal',
        'attack_probability': round(attack_prob, 4),
        'normal_probability': round(1 - attack_prob, 4),
        'threshold': current_threshold,
        'category': category,
        'specific_type': specific,
        'severity': severity,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'features': {k: str(v) for k, v in features_dict.items() if k in KDD_COLUMNS[:10]}
    }
    
    # Add to alert history if attack
    if is_attack:
        top_factors = []
        if str(features_dict.get('flag', '')).upper() in ['S0', 'S1', 'S2', 'REJ', 'RSTO']:
            top_factors.append(f"TCP Flag mencurigakan ({features_dict.get('flag', 'N/A')})")
        if float(features_dict.get('count', 0)) > 50:
            top_factors.append(f"Lonjakan koneksi count ({features_dict.get('count', 0)})")
        if float(features_dict.get('serror_rate', 0)) > 0.5:
            top_factors.append(f"SYN error rate tinggi ({features_dict.get('serror_rate', 0)})")
        if float(features_dict.get('num_failed_logins', 0)) > 0:
            top_factors.append(f"Login gagal ({features_dict.get('num_failed_logins', 0)}x)")
        if float(features_dict.get('root_shell', 0)) > 0:
            top_factors.append("Aktivitas root_shell terdeteksi")
        if not top_factors:
            top_factors.append(f"Probabilitas serangan tinggi ({attack_prob:.2%})")
        
        alert = {
            'id': f"ALT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'timestamp': result['timestamp'],
            'protocol_type': str(features_dict.get('protocol_type', 'N/A')),
            'service': str(features_dict.get('service', 'N/A')),
            'flag': str(features_dict.get('flag', 'N/A')),
            'src_bytes': float(features_dict.get('src_bytes', 0)),
            'dst_bytes': float(features_dict.get('dst_bytes', 0)),
            'count': float(features_dict.get('count', 0)),
            'attack_prob': attack_prob,
            'category': category,
            'specific_type': specific,
            'severity': severity,
            'status': 'New',
            'analyst_notes': f"Terdeteksi otomatis via Analisis Model (Threshold: {current_threshold})",
            'top_factors': top_factors
        }
        alert_history.insert(0, alert)
        save_alert_history()
    
    return result


# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/dashboard')
def api_dashboard():
    """Data untuk halaman Dashboard."""
    eval_results = {}
    eval_path = os.path.join(MODEL_DIR, 'evaluation_results.json')
    if os.path.exists(eval_path):
        with open(eval_path, 'r') as f:
            eval_results = json.load(f)
    
    # Calculate alert severity distribution
    severity_dist = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    status_dist = {'New': 0, 'Investigating': 0, 'Resolved': 0}
    for a in alert_history:
        sev = a.get('severity', 'Low')
        stat = a.get('status', 'New')
        severity_dist[sev] = severity_dist.get(sev, 0) + 1
        status_dist[stat] = status_dist.get(stat, 0) + 1
    
    return jsonify({
        'stats': prediction_stats,
        'threshold': current_threshold,
        'model_loaded': current_pipeline is not None,
        'model_name': current_model_info.get('model_name', 'N/A') if current_model_info else 'N/A',
        'total_alerts': len(alert_history),
        'severity_distribution': severity_dist,
        'status_distribution': status_dist,
        'recent_alerts': alert_history[:5],
        'eval_results': eval_results
    })


@app.route('/api/predict', methods=['POST'])
def api_predict():
    """Prediksi satu koneksi via form manual."""
    if current_pipeline is None:
        return jsonify({'error': 'Model belum dimuat! Silakan muat model terlebih dahulu.'}), 400
    
    data = request.json
    if not data:
        return jsonify({'error': 'Data tidak valid'}), 400
    
    try:
        result = predict_connection(data)
        return jsonify(result)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/predict_csv', methods=['POST'])
def api_predict_csv():
    """Prediksi batch dari file CSV."""
    if current_pipeline is None:
        return jsonify({'error': 'Model belum dimuat!'}), 400
    
    if 'file' not in request.files:
        return jsonify({'error': 'File CSV tidak ditemukan'}), 400
    
    file = request.files['file']
    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'Format file harus .csv'}), 400
    
    try:
        df = pd.read_csv(file)
        results = []
        
        for idx, row in df.iterrows():
            features = row.to_dict()
            result = predict_connection(features)
            result['row_index'] = idx
            results.append(result)
        
        # Summary
        attacks = sum(1 for r in results if r['prediction'] == 'Attack')
        normals = sum(1 for r in results if r['prediction'] == 'Normal')
        
        return jsonify({
            'total': len(results),
            'attacks': attacks,
            'normals': normals,
            'results': results,
            'summary': {
                'attack_rate': round(attacks / len(results) * 100, 2) if results else 0,
                'avg_attack_prob': round(
                    np.mean([r['attack_probability'] for r in results if r['prediction'] == 'Attack']), 4
                ) if attacks > 0 else 0
            }
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts')
def api_alerts():
    """Riwayat alert."""
    severity = request.args.get('severity', None)
    status = request.args.get('status', None)
    category = request.args.get('category', None)
    
    filtered = alert_history
    if severity:
        filtered = [a for a in filtered if a.get('severity') == severity]
    if status:
        filtered = [a for a in filtered if a.get('status') == status]
    if category:
        filtered = [a for a in filtered if a.get('category') == category]
    
    return jsonify({
        'total': len(filtered),
        'alerts': filtered
    })


@app.route('/api/alerts/<alert_id>/status', methods=['PUT'])
def api_update_alert_status(alert_id):
    """Update status alert."""
    data = request.json
    new_status = data.get('status', 'New')
    notes = data.get('analyst_notes', '')
    
    for alert in alert_history:
        if alert['id'] == alert_id:
            alert['status'] = new_status
            if notes:
                alert['analyst_notes'] = notes
            save_alert_history()
            return jsonify({'success': True, 'alert': alert})
    
    return jsonify({'error': 'Alert tidak ditemukan'}), 404


@app.route('/api/evaluate')
def api_evaluate():
    """Evaluasi model pada data test."""
    if current_pipeline is None:
        return jsonify({'error': 'Model belum dimuat!'}), 400
    
    # Find test data
    test_files = []
    for d in [DATA_DIR, BASE_DIR]:
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith('.csv') and ('test' in f.lower() or 'sample' in f.lower()):
                    test_files.append(os.path.join(d, f))
    
    if not test_files:
        # Return saved evaluation
        eval_path = os.path.join(MODEL_DIR, 'evaluation_results.json')
        if os.path.exists(eval_path):
            with open(eval_path, 'r') as f:
                return jsonify(json.load(f))
        return jsonify({'error': 'Data test tidak ditemukan'}), 404
    
    # Use sample_kdd_test.csv for demo
    test_file = test_files[0]
    for tf in test_files:
        if 'sample_kdd' in tf.lower():
            test_file = tf
            break
    
    try:
        df = pd.read_csv(test_file)
        
        # Find label
        label_col = None
        for col in ['ground_truth_label', 'class', 'label', 'attack_type']:
            if col in df.columns:
                label_col = col
                break
        
        if label_col is None:
            return jsonify({'error': 'Kolom label tidak ditemukan di data test'}), 400
        
        # Clean label
        df[label_col] = df[label_col].astype(str).str.strip().str.lower()
        df['clean_label'] = df[label_col].apply(
            lambda x: x.split('(')[0].strip().rstrip('.') if '(' in str(x) else str(x).strip().rstrip('.')
        )
        df['binary_label'] = df['clean_label'].apply(
            lambda x: 0 if x == 'normal' else 1
        )
        df['attack_category'] = df['clean_label'].map(
            lambda x: ATTACK_CATEGORY_MAP.get(x, 'Unknown')
        )
        
        # Add log features
        for col in ['duration', 'src_bytes', 'dst_bytes']:
            if col in df.columns:
                df[f'{col}_log1p'] = np.log1p(df[col].astype(float))
        
        feature_cols = current_model_info.get('feature_columns', [])
        drop_cols = [label_col, 'binary_label', 'clean_label', 'attack_category']
        if 'difficulty' in df.columns:
            drop_cols.append('difficulty')
        
        if not feature_cols:
            feature_cols = [c for c in df.columns if c not in drop_cols]
        
        # Ensure all columns exist
        for mc in set(feature_cols) - set(df.columns):
            df[mc] = 0
        
        X_test = df[feature_cols]
        y_test = df['binary_label']
        
        y_pred = current_pipeline.predict(X_test)
        y_prob = current_pipeline.predict_proba(X_test)[:, 1]
        
        # Apply threshold
        y_pred_thresh = (y_prob >= current_threshold).astype(int)
        
        cm = confusion_matrix(y_test, y_pred_thresh).tolist()
        acc = float(accuracy_score(y_test, y_pred_thresh))
        prec = float(precision_score(y_test, y_pred_thresh, zero_division=0))
        rec = float(recall_score(y_test, y_pred_thresh, zero_division=0))
        f1 = float(f1_score(y_test, y_pred_thresh, zero_division=0))
        
        report = classification_report(y_test, y_pred_thresh,
                                       target_names=['Normal', 'Attack'],
                                       output_dict=True)
        
        # Per-category analysis
        categories = df['attack_category'].unique()
        per_category = {}
        for cat in categories:
            mask = df['attack_category'] == cat
            if mask.sum() > 0:
                cat_true = y_test[mask]
                cat_pred = y_pred_thresh[mask]
                cat_correct = (cat_true == cat_pred).sum()
                per_category[cat] = {
                    'total': int(mask.sum()),
                    'correct': int(cat_correct),
                    'accuracy': round(float(cat_correct / mask.sum()), 4)
                }
        
        eval_result = {
            'accuracy': round(acc, 4),
            'precision': round(prec, 4),
            'recall': round(rec, 4),
            'f1_score': round(f1, 4),
            'confusion_matrix': cm,
            'classification_report': report,
            'per_category': per_category,
            'test_file': os.path.basename(test_file),
            'test_samples': int(len(y_test)),
            'threshold_used': current_threshold,
            'evaluated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Save
        with open(os.path.join(MODEL_DIR, 'evaluation_results.json'), 'w') as f:
            json.dump(eval_result, f, indent=2)
        
        return jsonify(eval_result)
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/model_info')
def api_model_info():
    """Info model aktif."""
    if current_model_info is None:
        return jsonify({'error': 'Model belum dimuat'}), 404
    
    info = dict(current_model_info)
    info['model_loaded'] = current_pipeline is not None
    info['model_file'] = os.path.join(MODEL_DIR, 'rf_pipeline.pkl')
    info['model_file_exists'] = os.path.exists(os.path.join(MODEL_DIR, 'rf_pipeline.pkl'))
    
    if os.path.exists(os.path.join(MODEL_DIR, 'rf_pipeline.pkl')):
        info['model_file_size'] = os.path.getsize(os.path.join(MODEL_DIR, 'rf_pipeline.pkl'))
    
    return jsonify(info)


@app.route('/api/model/reload', methods=['POST'])
def api_reload_model():
    """Reload model dari file."""
    success = load_model()
    if success:
        return jsonify({'success': True, 'message': 'Model berhasil dimuat ulang'})
    return jsonify({'error': 'Gagal memuat model'}), 500


@app.route('/api/model/upload', methods=['POST'])
def api_upload_model():
    """Upload model .pkl baru."""
    if 'file' not in request.files:
        return jsonify({'error': 'File tidak ditemukan'}), 400
    
    file = request.files['file']
    if not file.filename.endswith('.pkl'):
        return jsonify({'error': 'Format harus .pkl'}), 400
    
    try:
        filepath = os.path.join(MODEL_DIR, 'rf_pipeline.pkl')
        file.save(filepath)
        success = load_model()
        if success:
            return jsonify({'success': True, 'message': 'Model baru berhasil dimuat'})
        return jsonify({'error': 'Model tidak valid'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/threshold', methods=['GET'])
def api_get_threshold():
    """Get current threshold."""
    return jsonify({
        'threshold': current_threshold,
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


@app.route('/api/threshold', methods=['POST'])
def api_set_threshold():
    """Set decision threshold."""
    global current_threshold
    
    data = request.json
    new_threshold = float(data.get('threshold', 0.5))
    
    if not (0.01 <= new_threshold <= 0.99):
        return jsonify({'error': 'Threshold harus antara 0.01 dan 0.99'}), 400
    
    current_threshold = new_threshold
    
    # Save to config
    config = {
        'decision_threshold': current_threshold,
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    with open(os.path.join(BASE_DIR, 'system_config.json'), 'w') as f:
        json.dump(config, f, indent=2)
    
    return jsonify({
        'success': True,
        'threshold': current_threshold,
        'message': f'Threshold berhasil diubah ke {current_threshold}'
    })


@app.route('/api/upload_dataset', methods=['POST'])
def api_upload_dataset():
    """Upload dataset baru."""
    if 'file' not in request.files:
        return jsonify({'error': 'File tidak ditemukan'}), 400
    
    file = request.files['file']
    if not (file.filename.endswith('.csv') or file.filename.endswith('.txt')):
        return jsonify({'error': 'Format harus .csv atau .txt'}), 400
    
    try:
        filepath = os.path.join(DATA_DIR, file.filename)
        file.save(filepath)
        
        # Verify
        df = pd.read_csv(filepath)
        
        return jsonify({
            'success': True,
            'message': f'Dataset berhasil diupload: {file.filename}',
            'rows': len(df),
            'columns': len(df.columns),
            'column_names': list(df.columns),
            'filepath': filepath
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/retrain', methods=['POST'])
def api_retrain():
    """Retrain model dengan data baru."""
    success = train_quick_model()
    if success:
        return jsonify({'success': True, 'message': 'Model berhasil dilatih ulang'})
    return jsonify({'error': 'Gagal melatih model'}), 500


# ============================================================
# INITIALIZATION
# ============================================================

def initialize():
    """Initialize the application."""
    print("\n" + "=" * 60)
    print("  AI-ASSISTED SECURITY ANALYTICS PROTOTYPE")
    print("  Deteksi Intrusi Jaringan - NSL-KDD")
    print("=" * 60)
    
    load_threshold()
    load_alert_history()
    
    if not load_model():
        print("[WARNING] Model tidak dapat dimuat. Gunakan menu Manajemen Model.")
    
    print("\n[READY] Sistem siap digunakan!")
    print("=" * 60 + "\n")


# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    initialize()
    print("\n[*] Buka browser: http://localhost:5000\n")
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
