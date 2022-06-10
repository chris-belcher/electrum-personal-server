from setuptools import setup, find_packages

setup(
    name="electrum-personal-server",
    version="0.2.4",
    description="Electrum Personal Server",
    author="Chris Belcher",
    license="MIT",
    include_package_data=True,
    packages=find_packages(exclude=["tests"]),
    tests_require=["pytest"],
    entry_points={
        "console_scripts": [
            "electrum-personal-server = electrumpersonalserver.server.common:main",
        ]
    },
    package_data={"electrumpersonalserver": ["certs/*"]},
    data_files=[
        ("share/doc/electrum-personal-server", ["README.md",
                                                "config.ini_sample"]),
    ],
)
