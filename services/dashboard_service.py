from database.db import (
    get_dashboard_data,
    get_recent_analyses,
)


def load_dashboard():
    dashboard = get_dashboard_data()

    dashboard["recent"] = get_recent_analyses()

    return dashboard
