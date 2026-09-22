from setuptools import setup, find_packages

setup(
    name="phantom-scan",
    version="0.1.0-alpha",
    description="Adaptive timing-based stealth network scanner with evasion capabilities",
    author="Nyoul Labs",
    author_email="nyuollabs.dev@gmail.com",
    python_requires=">=3.9",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=open("requirements.txt").read().strip().split("\n"),
    entry_points={
        "console_scripts": [
            "phantom-scan=src.core.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Network Security",
        "Topic :: System :: Networking",
    ],
)
