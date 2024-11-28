# train_model.py

import os
import numpy as np
from feature_extractor import extract_features
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
from sklearn.preprocessing import StandardScaler
from sklearn.utils import class_weight
import matplotlib.pyplot as plt
import tensorflow as tf
from tensorflow.keras import layers, models
from tensorflow.keras.callbacks import EarlyStopping
import joblib

def create_dataset(benign_dir, malware_dir):
    data = []
    labels = []

    # Process benign files
    for filename in os.listdir(benign_dir):
        file_path = os.path.join(benign_dir, filename)
        features = extract_features(file_path)
        if features is not None:
            data.append(features)
            labels.append(0)  # Label for benign files

    # Process malware files
    for filename in os.listdir(malware_dir):
        file_path = os.path.join(malware_dir, filename)
        features = extract_features(file_path)
        if features is not None:
            data.append(features)
            labels.append(1)  # Label for malware files

    return np.array(data), np.array(labels)

if __name__ == '__main__':
    benign_dir = 'data/benign'
    malware_dir = 'data/malware'

    print("Creating dataset...")
    X, y = create_dataset(benign_dir, malware_dir)

    # Handle missing values (if any)
    if len(X) == 0 or len(y) == 0:
        print("No data available for training.")
        exit()

    print(f"Dataset size: {len(X)} samples.")

    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    # Scale features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # Save the scaler
    scaler_path = 'models/scaler.pkl'
    joblib.dump(scaler, scaler_path)
    print(f"Scaler saved to {scaler_path}")

    # Compute class weights to handle class imbalance
    class_weights = class_weight.compute_class_weight(
        class_weight='balanced',
        classes=np.unique(y_train),
        y=y_train
    )
    class_weights = dict(enumerate(class_weights))

    # Build the neural network model
    print("Building the model...")
    model = models.Sequential()
    model.add(layers.Input(shape=(X_train.shape[1],)))
    model.add(layers.Dense(64, activation='relu'))
    model.add(layers.Dropout(0.5))
    model.add(layers.Dense(32, activation='relu'))
    model.add(layers.Dropout(0.5))
    model.add(layers.Dense(1, activation='sigmoid'))

    # Compile the model
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    # Early stopping callback
    early_stopping = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)

    # Train the model
    print("Training the model...")
    history = model.fit(
        X_train, y_train,
        epochs=50,
        batch_size=32,
        validation_data=(X_test, y_test),
        callbacks=[early_stopping],
        class_weight=class_weights
    )

    # Evaluate the model
    print("Evaluating the model...")
    y_pred_prob = model.predict(X_test)
    y_pred = (y_pred_prob > 0.5).astype("int32")
    print(classification_report(y_test, y_pred))

    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=[0, 1])
    disp.plot()
    plt.show()

    # Save the model
    model_path = 'models/malware_detector.h5'
    model.save(model_path)
    print(f"Model saved to {model_path}")
