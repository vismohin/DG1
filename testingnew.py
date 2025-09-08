# data_processor.py

import csv
import json
import logging
from datetime import datetime

# --- Configuration Section ---
# This section defines various parameters and settings for the data processing.
# In a real-world application, these might be loaded from a configuration file.

INPUT_FILE_PATH = 'input_data.csv'
OUTPUT_FILE_PATH = 'processed_data.json'
LOG_FILE_PATH = 'data_processor.log'
DELIMITER = ','
ENCODING = 'utf-8'
BATCH_SIZE = 1000  # Process data in chunks for memory efficiency

# Configure logging
logging.basicConfig(filename=LOG_FILE_PATH, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Data Validation Rules ---
# Define rules for validating individual data fields.
VALIDATION_RULES = {
    'id': lambda x: isinstance(x, int) and x > 0,
    'name': lambda x: isinstance(x, str) and len(x) > 0,
    'email': lambda x: '@' in x and '.' in x,  # Basic email validation
    'age': lambda x: isinstance(x, int) and 0 <= x <= 120,
    'created_at': lambda x: isinstance(x, str) and len(x) == 10  # YYYY-MM-DD
}

# --- Helper Functions ---
# Utility functions to assist with data processing tasks.

def parse_date(date_str):
    """Parses a date string into a datetime object."""
    try:
        return datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        logging.warning(f"Invalid date format: {date_str}")
        return None

def clean_string(text):
    """Removes leading/trailing whitespace and converts to lowercase."""
    if isinstance(text, str):
        return text.strip().lower()
    return text

def validate_record(record):
    """Validates a single data record against defined rules."""
    is_valid = True
    for field, rule in VALIDATION_RULES.items():
        if field in record and not rule(record[field]):
            logging.warning(f"Validation failed for record ID {record.get('id')}: Field '{field}' failed rule.")
            is_valid = False
    return is_valid

# --- Core Processing Logic ---
# Functions that encapsulate the main data transformation steps.

def read_data(file_path, delimiter, encoding):
    """Reads data from a CSV file and yields records."""
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                yield row
    except FileNotFoundError:
        logging.error(f"Input file not found: {file_path}")
        raise
    except Exception as e:
        logging.error(f"Error reading input file: {e}")
        raise

def transform_data(record):
    """Applies transformations to a single data record."""
    transformed = record.copy()
    transformed['name'] = clean_string(transformed.get('name', ''))
    transformed['email'] = clean_string(transformed.get('email', ''))
    transformed['age'] = int(transformed.get('age', 0)) # Convert to int
    transformed['created_at_dt'] = parse_date(transformed.get('created_at', ''))
    # Add more complex transformations here as needed
    return transformed

def write_data(file_path, data, encoding):
    """Writes processed data to a JSON file."""
    try:
        with open(file_path, 'w', encoding=encoding) as f:
            json.dump(data, f, indent=4, default=str) # default=str handles datetime objects
    except Exception as e:
        logging.error(f"Error writing output file: {e}")
        raise

# --- Main Execution Flow ---

def main():
    """Orchestrates the data processing pipeline."""
    processed_records = []
    record_count = 0
    valid_record_count = 0

    logging.info(f"Starting data processing from {INPUT_FILE_PATH}...")

    try:
        for record in read_data(INPUT_FILE_PATH, DELIMITER, ENCODING):
            record_count += 1
            if validate_record(record):
                transformed_record = transform_data(record)
                processed_records.append(transformed_record)
                valid_record_count += 1
            else:
                logging.warning(f"Skipping invalid record: {record}")

            # Process in batches to manage memory
            if len(processed_records) >= BATCH_SIZE:
                logging.info(f"Processed {len(processed_records)} records in a batch.")
                # In a larger system, you might write to an intermediate store here.
                # For this example, we accumulate and write at the end.

        logging.info(f"Finished reading {record_count} records. {valid_record_count} valid records found.")
        write_data(OUTPUT_FILE_PATH, processed_records, ENCODING)
        logging.info(f"Processed data written to {OUTPUT_FILE_PATH}")

    except Exception as e:
        logging.critical(f"A critical error occurred during processing: {e}", exc_info=True)

if __name__ == '__main__':
    main()