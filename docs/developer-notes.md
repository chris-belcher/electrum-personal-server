# Developer notes for Electrum Personal Server

Please keep lines under 80 characters in length and ideally don't add
any external dependencies to keep this as easy to install as possible.

The project tries to follow the [python style guide PEP 8](https://www.python.org/dev/peps/pep-0008/).

## Naming

Do not use the acronym EPS. Acronyms are not very user-friendly and are hard to
search for.

## Installing in developer mode

To seamlessly work on the codebase while using `pip`, you need to
install in the `develop`/`editable` mode.  You can do that with:

    $ pip3 install --user -e /path/to/repo

`/path/to/repo` can also be a relative path, so if you are in the
source directory, just use `.`.  This installs the scripts in the
usual places, but imports the package from the source directory.  This
way, any changes you make are immediately visible.

## Maintainable code

Read the article [How To Write Unmaintainable Code](https://github.com/Droogans/unmaintainable-code/blob/master/README.md) and do the opposite of what it says.

## Commits

Commits should be [atomic](https://en.wikipedia.org/wiki/Atomic_commit#Atomic_commit_convention) and diffs should be easy to read.

Commit messages should be verbose by default consisting of a short subject line
(50 chars max), a blank line and detailed explanatory text as separate
paragraph(s), unless the title alone is self-explanatory (like "Corrected typo
in server.py") in which case a single title line is sufficient. Commit messages
should be helpful to people reading your code in the future, so explain the
reasoning for your decisions. Further explanation
[here](https://chris.beams.io/posts/git-commit/).

## Testing

Electrum Personal Server also works on [testnet](https://en.bitcoin.it/wiki/Testnet),
[regtest](https://bitcoin.org/en/glossary/regression-test-mode) and
[signet](https://en.bitcoin.it/wiki/Signet). The Electrum wallet can be started
in testnet mode with the command line flag `--testnet`, `--regtest` or `--signet`.

pytest is used for automated testing. On Debian-like systems install with
`pip3 install pytest pytest-cov`

Run the tests with:

    $ PYTHONPATH=.:$PYTHONPATH pytest

Create the coverage report with:

    $ PYTHONPATH=.:$PYTHONPATH pytest --cov-report=html --cov
    $ open htmlcov/index.html

If you have installed Electrum Personal Server with pip, there is no
need to set `PYTHONPATH`.  You could also run the tests with:

    $ python3 setup.py test

## Packaged binary release with pyinstaller

Pyinstaller is used to create the packaged binary releases. To build run:

    pyinstaller common.spec

This is best done on a virtual machine with the target OS installed. The
`cert/` directory needs to be copied and for windows its helpful to run
`unix2dos config.ini_sample` to convert the line endings.

