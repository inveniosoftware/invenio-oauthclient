# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015 CERN.
#
# Invenio is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# Invenio is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Invenio; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307, USA.
#
# In applying this license, CERN does not waive the privileges and immunities
# granted to it by virtue of its status as an Intergovernmental Organization
# or submit itself to any jurisdiction.

"""Invenio module that provides OAuth web authorization support."""

import os
import sys

from setuptools import find_packages, setup
from setuptools.command.test import test as TestCommand

readme = open('README.rst').read()
history = open('CHANGES.rst').read()

tests_require = [
    'Flask-CLI>=0.2.1',
    'check-manifest>=0.25',
    'coverage>=4.0',
    'httpretty>=0.8.10',
    'isort>=4.2.2',
    'mock>=1.3.0',
    'pep257>=0.7.0',
    'pytest-cache>=1.0',
    'pytest-cov>=1.8.0',
    'pytest-pep8>=1.0.6',
    'pytest>=2.8.0',
    'simplejson>=3.8',
]

extras_require = {
    'docs': [
        "Sphinx>=1.3",
    ],
    'tests': tests_require,
    'github': [
        'github3.py>=0.9',
    ],
}

extras_require['all'] = []
for reqs in extras_require.values():
    extras_require['all'].extend(reqs)

setup_requires = [
    'Babel>=1.3',
]

install_requires = [
    'cryptography>=0.6',  # sqlalchemy-utils dependency
    'Flask>=0.10.1',
    'Flask-BabelEx>=0.9.2',
    'Flask-Breadcrumbs>=0.3.0',
    'Flask-OAuthlib>=0.6.0,<0.7',  # quick fix for issue invenio#2158
    'Flask-Security>=1.7.5',
    'invenio-accounts>=1.0.0a6',
    'invenio-db>=1.0.0a4',
    # FIXME
    #  'invenio-upgrader>=0.1.0',
    # FIXME new oauthlib release after 0.7.2 has some compatible problems with
    # the used Flask-Oauthlib version.
    'oauthlib==0.7.2',
    'six>=1.7.2',
    'sqlalchemy-utils>=0.31',
    'uritools>=1.0.1',
]

packages = find_packages()


class PyTest(TestCommand):
    """PyTest Test."""

    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        """Init pytest."""
        TestCommand.initialize_options(self)
        self.pytest_args = []
        try:
            from ConfigParser import ConfigParser
        except ImportError:
            from configparser import ConfigParser
        config = ConfigParser()
        config.read('pytest.ini')
        self.pytest_args = config.get('pytest', 'addopts').split(' ')

    def finalize_options(self):
        """Finalize pytest."""
        TestCommand.finalize_options(self)
        if hasattr(self, '_test_args'):
            self.test_suite = ''
        else:
            self.test_args = []
            self.test_suite = True

    def run_tests(self):
        """Run tests."""
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)

# Get the version string. Cannot be done with import!
g = {}
with open(os.path.join('invenio_oauthclient', 'version.py'), 'rt') as fp:
    exec(fp.read(), g)
    version = g['__version__']

setup(
    name='invenio-oauthclient',
    version=version,
    description=__doc__,
    long_description=readme + '\n\n' + history,
    keywords='invenio oauth authentication',
    license='GPLv2',
    author='CERN',
    author_email='info@invenio-software.org',
    url='https://github.com/inveniosoftware/invenio-oauthclient',
    packages=packages,
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    entry_points={
        'invenio_base.apps': [
            'invenio_oauthclient = invenio_oauthclient:InvenioOAuthClient',
        ],
        'invenio_base.blueprints': [
            'invenio_oauthclient = invenio_oauthclient.views.client:blueprint',
            'invenio_oauthclient_settings = '
            'invenio_oauthclient.views.settings:blueprint',
        ],
        'invenio_db.models': [
            'invenio_oauthclient = invenio_oauthclient.models',
        ],
        'invenio_i18n.translations': [
            'invenio_oauthclient = invenio_oauthclient',
        ],
    },
    extras_require=extras_require,
    install_requires=install_requires,
    setup_requires=setup_requires,
    tests_require=tests_require,
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Development Status :: 1 - Planning',
    ],
    cmdclass={'test': PyTest},
)
