
import pytest

from electrumpersonalserver.server import parse_electrum_master_public_key


@pytest.mark.parametrize(
    "bad_master_public_key",
    [
    "zpub661MyMwAqRbcGVQTLtBFzc3ENvyZHoUEhWRdGwoqLZaf5wXP9VcDY2VJV7usvsFLZz" +
    "2RUTVhCVXYXc3S8zpLyAFbDFcfrpUiwLoE9VWH2yz", #bad checksum
    "a tpubD6NzVbkrYhZ4YVMVzC7wZeRfz3bhqcHvV8M3UiULCfzFtLtp5nwvi6LnBQegrkx" +
    "YGPkSzXUEvcPEHcKdda8W1YShVBkhFBGkLxjSQ1Nx3cJ tpubD6NzVbkrYhZ4WjgNYq2nF" +
    "TbiSLW2SZAzs4g5JHLqwQ3AmR3tCWpqsZJJEoZuP5HAEBNxgYQhtWMezszoaeTCg6FWGQB" +
    "T74sszGaxaf64o5s", #unparsable m number
    "2 tpubD6NzVbkrYhZ4YVMVzC7wZeRfz3bhqcHvV8M3UiULCfzFtLtp5nwvi6LnBQegrkx" +
    "YGPkSzXUEvcPEHcKdda8W1YShVBkhFBGkLxjSQ1Nx3cJ Vpub5fAqpSRkLmvXwqbuR61M" +
    "aKMSwj5z5xUBwanaz3qnJ5MgaBDpFSLUvKTiNK9zHpdvrg2LHHXkKxSXBHNWNpZz9b1Vq" +
    "ADjmcCs3arSoxN3F3r", #inconsistent magic
    "e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d" +
    "5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442", #wrong length
    "e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d" +
    "5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442ZZ" #not hex
    ]
)

def test_parse_bad_mpk(bad_master_public_key):
    try:
        parse_electrum_master_public_key(bad_master_public_key, 5)
        raised_error = False
    except (ValueError, Exception):
        raised_error = True
    assert raised_error
