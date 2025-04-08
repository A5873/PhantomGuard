from setuptools import find_packages, setup

setup(
    name="phantomguard",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "click>=8.0.0",
        "rich>=10.0.0",
        "psutil>=5.9.0",
        "typing-extensions>=4.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "isort>=5.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
            "pre-commit>=2.20.0",
        ]
    },
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "phantomguard=phantomguard.cli:main",
        ],
    },
)
