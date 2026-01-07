#!/usr/bin/env python3
"""
Setup script for ChSecurityHeaderAnalyzer
"""

from setuptools import setup, find_packages
import os

# Read requirements
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

# Read README
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="ChSecurityHeaderAnalyzer",
    version="1.0.0",
    author="Ch4120N",
    author_email="Ch4120N@Proton.me",
    description="Comprehensive Security Header Analysis Tool",
    url="https://github.com/Ch4120N/ChSecurityHeaderAnalyzer",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        '': ['config/*.yaml', 'templates/*.html']
    },
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'chSecurityHeaderAnalyzer=chSecurityHeaderAnalyzer:main',
            'ch-sha=chSecurityHeaderAnalyzer:main'
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: GPLv3 License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Utilities"
    ],
    python_requires=">=3.7",
    keywords="security headers analyzer scanner http web-security",
    project_urls={
        "Bug Reports": "https://github.com/Ch4120N/ChSecurityHeaderAnalyzer/issues",
        "Source": "https://github.com/Ch4120N/ChSecurityHeaderAnalyzer",
    },
)