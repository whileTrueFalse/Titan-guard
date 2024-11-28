# antivirus.py

import os
import shutil
import numpy as np
from feature_extractor import extract_features
from tensorflow.keras.models import load_model
import joblib
import logging

class Antivirus:
    def __init__(self):
        self.quarantine_dir = os.path.join(os.getcwd(), 'quarantine')
        os.makedirs(self.quarantine_dir, exist_ok=True)

        # Load the trained neural network model
        model_path = 'models/malware_detector.h5'
        self.model = load_model(model_path)

        # Load the scaler
        scaler_path = 'models/scaler.pkl'
        self.scaler = joblib.load(scaler_path)

        # Log the expected number of features
        logging.debug(f"Scaler expects {self.scaler.n_features_in_} features.")
        logging.debug(f"Model expects input shape: {self.model.input_shape}")

    def scan_file(self, file_path):
        if not os.path.isfile(file_path):
            return f'File not found: {file_path}', None

        try:
            features = extract_features(file_path)
            if features is not None:
                # Reshape and scale features for prediction
                features = features.reshape(1, -1)
                logging.debug(f'Features shape: {features.shape}')
                features = self.scaler.transform(features)
                logging.debug(f'Scaled features shape: {features.shape}')

                # Predict using the neural network
                prediction = self.model.predict(features)
                logging.debug(f'Prediction shape: {prediction.shape}')
                probability = prediction[0][0]
                logging.debug(f'Predicted probability: {probability}')
                if probability > 0.5:
                    self.quarantine_file(file_path)
                    return f'Malware detected and quarantined: {file_path}', 'Quarantined'
                else:
                    return f'File is clean: {file_path}', 'Clean'
            else:
                return f'Could not extract features from {file_path}. Classified as Unknown.', 'Unknown'
        except Exception as e:
            logging.exception(f"Exception occurred during scanning of {file_path}")
            error_message = f'Error scanning {file_path}: {str(e)}'
            return error_message, 'Unknown'

    def quarantine_file(self, file_path):
        try:
            shutil.move(file_path, self.quarantine_dir)
            logging.info(f'File quarantined: {file_path}')
        except Exception as e:
            logging.error(f'Failed to quarantine {file_path}: {e}')
