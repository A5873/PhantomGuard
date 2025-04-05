#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="rootkithunter",
    version="0.1.0",
    author="Security Tools Team",
    author_email="security@example.com",
    description="Advanced security analysis tool for rootkit detection and system security",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/rootkithunter",
    project_urls={
        "Bug Tracker": "https://github.com/example/rootkithunter/issues",
        "Documentation": "https://github.com/example/rootkithunter/wiki",
        "Source Code": "https://github.com/example/rootkithunter",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "mypy>=0.940",
            "flake8>=4.0.0",
            "pre-commit>=2.17.0",
        ],
        "docs": [
            "sphinx>=4.4.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "rootkithunter=rootkithunter.main:main",
        ],
    },
)

