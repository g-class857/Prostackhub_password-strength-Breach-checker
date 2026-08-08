from database.db import get_all_analyses


def load_history():
    """
    Retrieve all password analyses.
    """
    return get_all_analyses()
