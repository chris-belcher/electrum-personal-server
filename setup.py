from setuptools import setup, find_packages

setup(
    name="electrum-personal-server",
    version="0.1.4.dev0",
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
    data_files=[
        ('etc/electrumpersonalserver/certs', ['certs/cert.crt', 'certs/cert.key'])
        ("etc/electrum-personal-server", ["config.cfg_sample"]),
        ("share/doc/electrum-personal-server", ["README.md"]),
    ],
    # install_requires=[
    #     'secp256k1'
    # ]
)
