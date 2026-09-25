"""WinHunt Flask application package.

This package provides the Flask application factory for the WinHunt platform.
"""

from flask import Flask

from app.routes.dashboard import dashboard_bp
from app.routes.investigation import investigation_bp
from app.routes.hunting import hunting_bp


def create_app() -> Flask:
    """Create and return a Flask application instance."""
    app = Flask(__name__)
    app.config.setdefault("JSON_SORT_KEYS", False)
    app.config.setdefault("TESTING", False)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(investigation_bp)
    app.register_blueprint(hunting_bp)
    return app


__all__ = ["create_app"]
