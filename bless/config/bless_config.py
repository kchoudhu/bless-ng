"""
.. module: bless.config.bless_config
    :copyright: (c) 2016 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.
"""
import configparser
import base64
import os
import re
import zlib
import bz2

BLESS_OPTIONS_SECTION = 'Bless Options'
CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION = 'certificate_validity_before_seconds'
CERTIFICATE_VALIDITY_AFTER_SEC_OPTION = 'certificate_validity_after_seconds'
CERTIFICATE_VALIDITY_SEC_DEFAULT = 60 * 2

ENTROPY_MINIMUM_BITS_OPTION = 'entropy_minimum_bits'
ENTROPY_MINIMUM_BITS_DEFAULT = 2048

RANDOM_SEED_BYTES_OPTION = 'random_seed_bytes'
RANDOM_SEED_BYTES_DEFAULT = 256

LOGGING_LEVEL_OPTION = 'logging_level'
LOGGING_LEVEL_DEFAULT = 'INFO'

TEST_USER_OPTION = 'test_user'
TEST_USER_DEFAULT = None

CERTIFICATE_EXTENSIONS_OPTION = 'certificate_extensions'
# These are the the ssh-keygen default extensions:
CERTIFICATE_EXTENSIONS_DEFAULT = 'permit-X11-forwarding,' \
                                 'permit-agent-forwarding,' \
                                 'permit-port-forwarding,' \
                                 'permit-pty,' \
                                 'permit-user-rc'

BLESS_CA_SECTION = 'Bless CA'
CA_PRIVATE_KEY_FILE_OPTION = 'ca_private_key_file'
CA_PRIVATE_KEY_OPTION = 'ca_private_key'
CA_PRIVATE_KEY_COMPRESSION_OPTION = 'ca_private_key_compression'
CA_PRIVATE_KEY_COMPRESSION_OPTION_DEFAULT = None

USERNAME_VALIDATION_OPTION = 'username_validation'
USERNAME_VALIDATION_DEFAULT = 'useradd'

REMOTE_USERNAMES_VALIDATION_OPTION = 'remote_usernames_validation'
REMOTE_USERNAMES_VALIDATION_DEFAULT = 'principal'

REMOTE_USERNAMES_BLACKLIST_OPTION = 'remote_usernames_blacklist'
REMOTE_USERNAMES_BLACKLIST_DEFAULT = None


class BlessConfig(configparser.RawConfigParser, object):
    def __init__(self, config_file):
        """
        Parses the BLESS config file, and provides some reasonable default values if they are
        absent from the config file.

        The [Bless Options] section is entirely optional, and has defaults.

        The [Bless CA] section is required.
        :param config_file: Path to the connfig file.
        """
        defaults = {CERTIFICATE_VALIDITY_BEFORE_SEC_OPTION: CERTIFICATE_VALIDITY_SEC_DEFAULT,
                    CERTIFICATE_VALIDITY_AFTER_SEC_OPTION: CERTIFICATE_VALIDITY_SEC_DEFAULT,
                    ENTROPY_MINIMUM_BITS_OPTION: ENTROPY_MINIMUM_BITS_DEFAULT,
                    RANDOM_SEED_BYTES_OPTION: RANDOM_SEED_BYTES_DEFAULT,
                    LOGGING_LEVEL_OPTION: LOGGING_LEVEL_DEFAULT,
                    TEST_USER_OPTION: TEST_USER_DEFAULT,
                    CERTIFICATE_EXTENSIONS_OPTION: CERTIFICATE_EXTENSIONS_DEFAULT,
                    USERNAME_VALIDATION_OPTION: USERNAME_VALIDATION_DEFAULT,
                    REMOTE_USERNAMES_VALIDATION_OPTION: REMOTE_USERNAMES_VALIDATION_DEFAULT,
                    REMOTE_USERNAMES_BLACKLIST_OPTION: REMOTE_USERNAMES_BLACKLIST_DEFAULT,
                    CA_PRIVATE_KEY_COMPRESSION_OPTION: CA_PRIVATE_KEY_COMPRESSION_OPTION_DEFAULT
                    }
        configparser.RawConfigParser.__init__(self, defaults=defaults)
        self.read(config_file)

        if not self.has_section(BLESS_CA_SECTION):
            self.add_section(BLESS_CA_SECTION)

        if not self.has_section(BLESS_OPTIONS_SECTION):
            self.add_section(BLESS_OPTIONS_SECTION)

    def getkmsauthkeyids(self):
        """
        Returns a list of kmsauth keys used for validation (so a key generated
        in one region can validate in another).
        :return: A list of kmsauth key ids
        """
        return list(map(str.strip, self.get(KMSAUTH_SECTION, KMSAUTH_KEY_ID_OPTION).split(',')))

    def getprivatekey(self):
        """
        Get a private key from either a file specified in the config file, or from an environment variable.  Env
        Vars in Lambda can't contain a 4096 RSA key uncompressed, so compressed keys are also supported.
        :return: byte string that contains the private key in PEM format (ascii).
        """
        compression = self.get(BLESS_CA_SECTION, CA_PRIVATE_KEY_COMPRESSION_OPTION)

        if self.has_option(BLESS_CA_SECTION, CA_PRIVATE_KEY_OPTION):
            return self._decompress(base64.b64decode(self.get(BLESS_CA_SECTION, CA_PRIVATE_KEY_OPTION)), compression)

        ca_private_key_file = self.get(BLESS_CA_SECTION, CA_PRIVATE_KEY_FILE_OPTION)

        # read the private key .pem
        with open(os.path.expanduser(ca_private_key_file), 'rb') as f:
            return self._decompress(f.read(), compression)

    def has_option(self, section, option):
        """
        Checks if an option exists.

        This will search in both the environment variables and in the config file
        :param section: The section to search in
        :param option: The option to check
        :return: True if it exists, False otherwise
        """
        environment_key = self._environment_key(section, option)
        if environment_key in os.environ:
            return True
        else:
            return super(BlessConfig, self).has_option(section, option)

    def get(self, section, option, **kwargs):
        """
        Gets a value from the configuration.

        Checks the environment  before looking in the config file.
        :param section: The config section to look in
        :param option: The config option to look at
        :return: The value of the config option
        """
        environment_key = self._environment_key(section, option)
        output = os.environ.get(environment_key, None)
        if output is None:
            output = super(BlessConfig, self).get(section, option, **kwargs)
        return output

    @staticmethod
    def _environment_key(section, option):
        return (re.sub('\W+', '_', section) + '_' + re.sub('\W+', '_', option)).lower()

    @staticmethod
    def _decompress(data, algorithm):
        """
        Decompress a byte string based of the provided algorithm.
        :param data: byte string
        :param algorithm: string  with the name of the compression algorithm used
        :return: decompressed byte string.
        """
        if algorithm is None or algorithm == 'none':
            result = data
        elif algorithm == 'zlib':
            result = zlib.decompress(data)
        elif algorithm == 'bz2':
            result = bz2.decompress(data)
        else:
            raise ValueError("Compression {} is not supported.".format(algorithm))

        return result
