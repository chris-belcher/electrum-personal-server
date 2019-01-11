from setuptools import setup, find_packages

setup(
    name="electrum-personal-server",
    version="0.1.6.dev0",
    description="Electrum Personal Server",
    author="Chris Belcher",
    license="MIT",
    include_package_data=True,
    packages=find_packages(exclude=["tests"]),
    setup_requires=["pytest-runner"],
    tests_require=["pytest"],
    entry_points={
        "console_scripts": [
            "electrum-personal-server = electrumpersonalserver.server.common:main",
            "electrum-personal-server-rescan = electrumpersonalserver.server.common:rescan",
        ]
    },
    package_data={"electrumpersonalserver": ["certs/*"]},
    data_files=[
        ("etc/electrum-personal-server", ["config.cfg_sample"]),
        ("share/doc/electrum-personal-server", ["README.md", "doc/tor.md"]),
    ],
    install_requires=[
        'wheel'
    ]
)
