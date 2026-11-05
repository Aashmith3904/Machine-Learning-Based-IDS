import pandas as pd
import numpy as np
import time
import pickle

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


def load_cicids(path="D:\\IDS\\CICIDS2017_FULL.csv"):
    print("\nLoading CICIDS2017 dataset...")
    data = pd.read_csv(path)

    data.columns = data.columns.str.strip()


    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    cols_to_drop = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
    data = data.drop(columns=[col for col in cols_to_drop if col in data.columns])

   
    cols_to_convert = data.columns.drop('Label')
    for col in cols_to_convert:
        if data[col].dtype == 'object':
            data[col] = pd.to_numeric(data[col], errors='coerce')

    data = data.dropna()



    encoder = LabelEncoder()
    data['Label'] = encoder.fit_transform(data['Label'])

    X = data.drop('Label', axis=1)
    y = data['Label']

    return X, y

def train_model(X, y):

    scaler = StandardScaler()
    X = scaler.fit_transform(X)


    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )


    import os
    num_cores = getattr(os, 'cpu_count', lambda: 4)() or 4
    chunk_size = max(10, num_cores)
    total_trees = 100

    model = RandomForestClassifier(
        n_estimators=0,
        warm_start=True,
        random_state=42,
        n_jobs=-1
    )

    print("\nTraining model...")
    from tqdm import tqdm
    start_time = time.time()

    with tqdm(total=total_trees, desc="Training Progress") as pbar:
        for current_trees in range(chunk_size, total_trees + chunk_size, chunk_size):
            current_trees = min(current_trees, total_trees)
            if current_trees <= model.n_estimators:
                continue

            added_trees = current_trees - model.n_estimators
            model.n_estimators = current_trees
            model.fit(X_train, y_train)
            pbar.update(added_trees)

    end_time = time.time()
    print("Training Time:", round(end_time - start_time, 2), "seconds")


    from tqdm import tqdm

    chunk_size = 50000
    y_pred = []
    
    print("\nPredicting...")
    for i in tqdm(range(0, len(X_test), chunk_size), desc="Validation Progress"):
        chunk = X_test[i:i + chunk_size]
        y_pred.extend(model.predict(chunk))

    y_pred = np.array(y_pred)

    print("\nAccuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))

    return model, scaler


class IDS:
    def __init__(self, cic_model, cic_scaler):
        self.cic_model = cic_model
        self.cic_scaler = cic_scaler

    def predict(self, X, format_type='cic'):
        if format_type.lower() == 'cic':
            X_scaled = self.cic_scaler.transform(X)
            return self.cic_model.predict(X_scaled)
        else:
            raise ValueError("format_type must be 'cic'")


def main():
    X_cic, y_cic = load_cicids(path="D:\\IDS\\CICIDS2017_FULL.csv")
    print("Training model on CICIDS2017 dataset...")
    model_cic, scaler_cic = train_model(X_cic, y_cic)
    
    ids_model = IDS(model_cic, scaler_cic)
    
    print("\nSaving IDS model to disk...")
    with open("D:\\IDS\\ids_model.pkl", "wb") as f:
        pickle.dump(ids_model, f)
        
    print("\nModel training and saving completed successfully.")

if __name__ == "__main__":
    main()