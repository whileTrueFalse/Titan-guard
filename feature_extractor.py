# feature_extractor.py

import numpy as np
import logging

def extract_features(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            if len(content) == 0:
                logging.error(f"No data in file: {file_path}")
                return None

        # Limit to the first N bytes (e.g., 1024 bytes)
        content = content[:1024]

        # Convert to numpy array
        byte_array = np.frombuffer(content, dtype=np.uint8)

        # Calculate byte histogram (256 bins)
        byte_histogram = np.bincount(byte_array, minlength=256)
        histogram_sum = byte_histogram.sum()
        if histogram_sum == 0:
            logging.error(f"Empty byte histogram for file: {file_path}")
            return None
        byte_histogram = byte_histogram / histogram_sum  # Normalize

        # Select the first 54 features if needed
        features = byte_histogram[:54]

        return features
    except Exception as e:
        logging.error(f"Error extracting features from {file_path}: {e}", exc_info=True)
        return None
