#!/usr/bin/env python3
"""
Setup script for Duo Log Collector
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="duo-log-collector",
    version="1.0.0",
    author="Ibrahim",
    author_email="ibrahim@1b05h1n.com",
    description="A comprehensive Python toolkit for collecting and analyzing logs from Duo Security's Admin API",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/1B05H1N/duo-log-collector",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "duo-log-collector=src.duo_log_collector:main",
            "duo-auth-logs=src.duo_auth_logs_only:main",
            "duo-auth-analyzer=src.duo_auth_log_analyzer:main",
        ],
    },
    keywords="duo security logs authentication api monitoring security-analysis",
    project_urls={
        "Bug Reports": "https://github.com/1B05H1N/duo-log-collector/issues",
        "Source": "https://github.com/1B05H1N/duo-log-collector",
        "Documentation": "https://github.com/1B05H1N/duo-log-collector#readme",
    },
)
