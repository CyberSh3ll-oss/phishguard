from setuptools import setup

setup(
    name="phishguard",
    version="1.0.0",
    py_modules=["phishguard_simple"],
    install_requires=[
        "requests",
        "validators",
        "tldextract",
    ],
    entry_points={
        "console_scripts": [
            "phishguard = phishguard_simple:main",
        ],
    },
)
