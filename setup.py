#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name="ucutils",
    version="0.2.0",
    description="Convenience helpers for working with the Unicorn emulator",
    author="Willi Ballenthin",
    author_email="willi.ballenthin@gmail.com",
    url="https://github.com/williballenthin/ucutils",
    license="Apache License 2.0",
    install_requires=[
        "hexdump==3.3",
        "unicorn==2.0.1.post1",
        "capstone==4.0.2",
    ],
    extras_require={
        "dev": [
            "pre-commit==3.3.3",
            "pytest==7.4.0",
            "pytest-sugar==0.9.7",
            "pytest-instafail==0.5.0",
            "pytest-cov==4.1.0",
        ],
    },
    packages=find_packages(exclude=["*.tests", "*.tests.*"]),
    entry_points={"console_scripts": []},
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.11",
    ],
)
