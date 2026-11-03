"""
train_model.py
==============
Script untuk melatih model Random Forest pada dataset NSL-KDD.
Mengikuti pipeline preprocessing dari laporan tugas P4:
  - Drop kolom 'difficulty' dan 'attack_category' (jika ada)
  - Tambahkan fitur log1p untuk duration, src_bytes, dst_bytes
  - OneHotEncoding pada protocol_type, service, flag
  - StandardScaler pada fitur numerik
  - RandomForestClassifier
Pipeline disimpan sebagai file .pkl untuk digunakan oleh aplikasi web.
"""

import os
import sys
import json
import warnings
import numpy as np
import pandas as pd
import joblib
from datetime import datetime

from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler, FunctionTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score, roc_auc_score
)

warnings.filterwarnings('ignore')

# ---------- KONFIGURASI ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# ---------- KOLOM NSL-KDD ----------
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

# Mapping tipe serangan ke kategori (sesuai laporan P2)
ATTACK_CATEGORY_MAP = {
    'normal': 'Normal',
    # DoS
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS',
    'smurf': 'DoS', 'teardrop': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS',
    'processtable': 'DoS', 'udpstorm': 'DoS',
    # Probe
    'satan': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    # R2L
    'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L',
    'multihop': 'R2L', 'warezmaster': 'R2L', 'warezclient': 'R2L',
    'spy': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 'snmpguess': 'R2L',
    'snmpgetattack': 'R2L', 'httptunnel': 'R2L', 'sendmail': 'R2L',
    'named': 'R2L', 'worm': 'R2L',
    # U2R
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'rootkit': 'U2R',
    'perl': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R',
    'httptunnel': 'R2L',
}


def load_kdd_data(filepath, has_header=True):
    """Load dan bersihkan data NSL-KDD."""
    if has_header:
        df = pd.read_csv(filepath)
    else:
        # Format tanpa header: 41 fitur + class + difficulty
        df = pd.read_csv(filepath, header=None)
        if df.shape[1] == 43:
            df.columns = KDD_COLUMNS + ['class', 'difficulty']
        elif df.shape[1] == 42:
            df.columns = KDD_COLUMNS + ['class']
        else:
            df.columns = KDD_COLUMNS[:df.shape[1]]

    return df


def preprocess_labels(df):
    """
    Buat label biner (normal=0, attack=1) dan kategori serangan.
    Sesuai laporan P2: target binary normal vs attack.
    """
    label_col = None
    for col in ['class', 'label', 'attack_type', 'target']:
        if col in df.columns:
            label_col = col
            break
    
    if label_col is None:
        raise ValueError("Kolom label tidak ditemukan dalam dataset!")

    # Bersihkan label
    df[label_col] = df[label_col].str.strip().str.lower().str.rstrip('.')

    # Mapping ke kategori
    df['attack_category'] = df[label_col].map(
        lambda x: ATTACK_CATEGORY_MAP.get(x, 'Unknown')
    )

    # Label biner: 0 = Normal, 1 = Attack
    df['binary_label'] = (df['attack_category'] != 'Normal').astype(int)

    return df, label_col


def add_log_features(df):
    """
    Tambahkan fitur log1p untuk fitur yang sangat skewed.
    Sesuai laporan P4: duration, src_bytes, dst_bytes.
    """
    for col in ['duration', 'src_bytes', 'dst_bytes']:
        if col in df.columns:
            df[f'{col}_log1p'] = np.log1p(df[col].astype(float))
    return df


def prepare_features(df, label_col):
    """
    Siapkan fitur X dan target y.
    Sesuai laporan P4: drop difficulty dan attack_category dari X.
    """
    drop_cols = [label_col, 'binary_label', 'attack_category']
    if 'difficulty' in df.columns:
        drop_cols.append('difficulty')

    feature_cols = [c for c in df.columns if c not in drop_cols]
    X = df[feature_cols]
    y = df['binary_label']
    
    return X, y, feature_cols


def build_pipeline(X):
    """
    Build sklearn Pipeline sesuai laporan P4:
    - OneHotEncoder untuk protocol_type, service, flag
    - StandardScaler untuk fitur numerik
    - RandomForestClassifier
    """
    cat_cols = [c for c in ['protocol_type', 'service', 'flag'] if c in X.columns]
    num_cols = [c for c in X.columns if c not in cat_cols]

    preprocessor = ColumnTransformer([
        ('num', StandardScaler(), num_cols),
        ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), cat_cols)
    ])

    pipeline = Pipeline([
        ('preprocess', preprocessor),
        ('clf', RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        ))
    ])

    return pipeline, num_cols, cat_cols


def train_and_save():
    """Main training function."""
    print("=" * 60)
    print("  TRAINING MODEL RANDOM FOREST - NSL-KDD")
    print("  Sesuai Pipeline Laporan P4 Kelompok")
    print("=" * 60)

    # ---- LOAD DATA ----
    # Cari dataset
    train_file = None
    test_file = None
    
    # Cek berbagai lokasi
    search_paths = [
        DATA_DIR,
        BASE_DIR,
        os.path.join(BASE_DIR, ".."),
    ]
    
    for sp in search_paths:
        for f in os.listdir(sp) if os.path.isdir(sp) else []:
            fl = f.lower()
            full = os.path.join(sp, f)
            if 'train' in fl and fl.endswith('.csv'):
                train_file = full
            elif 'test' in fl and fl.endswith('.csv') and 'sample' not in fl:
                test_file = full

    # Gunakan data sample yang tersedia jika tidak ada full dataset
    kdd_100 = os.path.join(BASE_DIR, "KDDTest_sample_100_rows.csv")
    sample_test = os.path.join(BASE_DIR, "sample_kdd_test.csv")

    if train_file is None:
        print("\n[INFO] Dataset KDDTrain+ tidak ditemukan.")
        print("[INFO] Menggunakan data sample untuk demo...")
        
        # Gunakan data yang ada
        if os.path.exists(kdd_100):
            train_file = kdd_100
        elif os.path.exists(sample_test):
            train_file = sample_test
        else:
            print("[ERROR] Tidak ada data training yang tersedia!")
            print("Letakkan KDDTrain+.csv di folder 'data/'")
            sys.exit(1)

    if test_file is None:
        if os.path.exists(sample_test):
            test_file = sample_test
        elif os.path.exists(kdd_100):
            test_file = kdd_100

    print(f"\n[DATA] Training: {train_file}")
    print(f"[DATA] Testing : {test_file}")

    # ---- LOAD & PREPROCESS ----
    print("\n[STEP 1] Loading data...")
    df_train = load_kdd_data(train_file)
    print(f"  Train shape: {df_train.shape}")

    df_train, label_col = preprocess_labels(df_train)

    print("\n[STEP 2] Menambahkan fitur log1p (sesuai P4)...")
    df_train = add_log_features(df_train)

    print("\n[STEP 3] Menyiapkan fitur...")
    X_train, y_train, feature_cols = prepare_features(df_train, label_col)
    print(f"  Jumlah fitur: {len(feature_cols)}")
    print(f"  Distribusi label training:")
    print(f"    Normal (0): {(y_train == 0).sum()}")
    print(f"    Attack (1): {(y_train == 1).sum()}")

    print("\n[STEP 4] Building pipeline (sesuai P4)...")
    pipeline, num_cols, cat_cols = build_pipeline(X_train)
    print(f"  Fitur numerik: {len(num_cols)}")
    print(f"  Fitur kategorikal: {len(cat_cols)}")

    print("\n[STEP 5] Training Random Forest...")
    pipeline.fit(X_train, y_train)
    print("  Training selesai!")

    # ---- EVALUASI ----
    if test_file:
        print("\n[STEP 6] Evaluasi pada data test...")
        df_test = load_kdd_data(test_file)
        
        # Sesuaikan kolom label
        test_label_col = None
        for col in ['class', 'label', 'attack_type', 'target', 'ground_truth_label']:
            if col in df_test.columns:
                test_label_col = col
                break
        
        if test_label_col:
            # Clean label
            df_test[test_label_col] = df_test[test_label_col].astype(str).str.strip().str.lower()
            
            # Parse label - handle format "neptune (DoS)" 
            df_test['clean_label'] = df_test[test_label_col].apply(
                lambda x: x.split('(')[0].strip().rstrip('.') if '(' in str(x) else str(x).strip().rstrip('.')
            )
            df_test['binary_label'] = df_test['clean_label'].apply(
                lambda x: 0 if x == 'normal' else 1
            )
            df_test['attack_category'] = df_test['clean_label'].map(
                lambda x: ATTACK_CATEGORY_MAP.get(x, 'Unknown')
            )
            
            df_test = add_log_features(df_test)
            
            # Prepare test features - pastikan kolom sama
            drop_test = [test_label_col, 'binary_label', 'attack_category', 'clean_label']
            if 'difficulty' in df_test.columns:
                drop_test.append('difficulty')
            
            test_features = [c for c in df_test.columns if c not in drop_test]
            
            # Pastikan fitur test match dengan train
            missing_cols = set(feature_cols) - set(test_features)
            extra_cols = set(test_features) - set(feature_cols)
            
            for mc in missing_cols:
                df_test[mc] = 0
            
            X_test = df_test[feature_cols]
            y_test = df_test['binary_label']
            
            y_pred = pipeline.predict(X_test)
            y_prob = pipeline.predict_proba(X_test)[:, 1]

            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, zero_division=0)
            rec = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            cm = confusion_matrix(y_test, y_pred)

            print(f"\n  Accuracy : {acc:.4f}")
            print(f"  Precision: {prec:.4f}")
            print(f"  Recall   : {rec:.4f}")
            print(f"  F1-Score : {f1:.4f}")
            print(f"\n  Confusion Matrix:")
            print(f"  {cm}")
            print(f"\n  Classification Report:")
            print(classification_report(y_test, y_pred,
                                        target_names=['Normal', 'Attack']))

            # Simpan metrik evaluasi
            eval_results = {
                'accuracy': float(acc),
                'precision': float(prec),
                'recall': float(rec),
                'f1_score': float(f1),
                'confusion_matrix': cm.tolist(),
                'test_samples': int(len(y_test)),
                'test_file': test_file,
                'evaluated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            eval_path = os.path.join(MODEL_DIR, 'evaluation_results.json')
            with open(eval_path, 'w') as f:
                json.dump(eval_results, f, indent=2)
            print(f"\n  Evaluasi disimpan: {eval_path}")

    # ---- SIMPAN MODEL ----
    print("\n[STEP 7] Menyimpan model pipeline...")
    
    model_info = {
        'model_name': 'RandomForest_NSL_KDD',
        'algorithm': 'Random Forest Classifier',
        'n_estimators': 100,
        'feature_columns': feature_cols,
        'num_columns': num_cols,
        'cat_columns': cat_cols,
        'n_features': len(feature_cols),
        'trained_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'train_file': train_file,
        'train_samples': int(len(y_train)),
        'version': '1.0'
    }

    model_path = os.path.join(MODEL_DIR, 'rf_pipeline.pkl')
    info_path = os.path.join(MODEL_DIR, 'model_info.json')
    
    joblib.dump(pipeline, model_path)
    with open(info_path, 'w') as f:
        json.dump(model_info, f, indent=2)

    print(f"  Pipeline: {model_path}")
    print(f"  Info    : {info_path}")
    print("\n" + "=" * 60)
    print("  TRAINING SELESAI! Model siap digunakan.")
    print("=" * 60)

    return pipeline, model_info


if __name__ == '__main__':
    train_and_save()
