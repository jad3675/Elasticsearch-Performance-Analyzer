import json

def save_json_report(analysis_data, filepath):
    """
    Saves the analysis data to a JSON file.

    :param analysis_data: The dictionary containing the analysis data.
    :param filepath: The path to the file where the JSON report will be saved.
    :return: A tuple (success, message).
    """
    if not analysis_data:
        return False, "No analysis data to export."

    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, indent=4)
        return True, f"Analysis report successfully saved to: {filepath}"
    except Exception as e:
        return False, f"Failed to export results to JSON: {str(e)}"