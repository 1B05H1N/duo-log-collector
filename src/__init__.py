"""
Duo Log Collector

A comprehensive Python toolkit for collecting and analyzing logs from Duo Security's Admin API.
"""

__version__ = "1.0.0"
__author__ = "Ibrahim"
__email__ = "ibrahim@1b05h1n.com"
__description__ = "A comprehensive Python toolkit for collecting and analyzing logs from Duo Security's Admin API"

# Import main classes for easy access
from .duo_log_collector import DuoAPIClient, DuoLogCollector
from .duo_auth_logs_only import DuoAuthLogCollector
from .duo_auth_log_analyzer import AuthenticationLogAnalyzer

__all__ = [
    'DuoAPIClient',
    'DuoLogCollector', 
    'DuoAuthLogCollector',
    'AuthenticationLogAnalyzer'
]
