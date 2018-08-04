"""TOR hidden service for Electrum Personal Server

@author Suvayu Ali
@date   2018-08-04

"""

import os
import logging
from configparser import ConfigParser
from importlib import import_module

def _from_stem_import_cls(module, cls):
    """Import Tor controller class.

    Since this adds an external dependency, strictly speaking, which is not
    necessary to use Electrum Personal Server, a failure to import `stem` is
    not a terminal failure.  Instead, report an error with instructions for
    solving the issue.

    This means the caller should check if the returned object `is not None`.

    """
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    try:
        cls = getattr(import_module(module), cls)
    except ImportError as err:
        logger.debug('could not import from `stem`', exc_info=True)
        logger.error('please install the `stem` package for Tor support')
    else:
        return cls


def hs_options(overrides=[]):
    """Default ephemeral hidden service options

    Options can be overridden by passing an override dictionary.

    """
    opts = {
        'key_type': 'NEW',
        'key_content': 'BEST',
        'discard_key': False,
        'await_publication': True,
        'basic_auth': {'bob': None},
    }
    opts.update(overrides)
    return opts.copy()


def hs_restore(config):
    """Restore the private key and authentication credentials from config."""
    res = {
        'key_type': config.get('tor-hidden-service', 'private_key_type'),
        'key_content': config.get('tor-hidden-service', 'private_key'),
        'basic_auth': {'bob': config.get('tor-hidden-service', 'auth')}
    }
    return res


def hs_store(key, store):
    """Save the private key and authentication credentials

    On first run, the private key and authentication credentials are stored in
    a sub pickle file on disk.  `store` is the path to the pickle file.

    """
    return NotImplemented


def start_tor_hidden_service(config, firstrun=False):
    logger = logging.getLogger('ELECTRUMPERSONALSERVER')
    Controller = _from_stem_import_cls(module='stem.control', cls='Controller')
    if Controller is None:
        logger.error('Tor hidden service not started')
        return None, None
    else:
        version = _from_stem_import_cls(module='stem', cls='__version__')
        majv, minv = version.split('.', 3)[:2]
        ControlError = _from_stem_import_cls(module='stem', cls='ControlError')
        if majv >= 1 and minv >= 7:  # new in 1.7
            Timeout = _from_stem_import_cls(module='stem', cls='Timeout')
            errs = (ControlError, Timeout)
        else:
            errs = ControlError

    # TODO: check if tor is running
    with Controller.from_port(port=9051) as ctrlr:
        # TODO: multiple authentication methods
        ctrlr.authenticate()

        opts = hs_options([] if firstrun else hs_restore(config))
        try:
            hsv = ctrlr.create_ephemeral_hidden_service(50002, **opts)
        except errs as err:
            logger.debug('', exc_info=True)
            logger.info('could not create hidden service, cleaning up')
            ctrlr.close()
            return None, None
        else:
            logger.info('hidden service onion: {}.onion'.format(hsv.service_id))
            # ADD_ONION response does not include auth when provided in options
            logger.info('hidden service auth: {}'.format(
                hsv.client_auth.get('bob', opts['basic_auth'].get('bob'))))
            return ctrlr, hsv
