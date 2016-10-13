from setuptools import setup, find_packages

requirements = [
    'iso8601',
    'pytz',
    'requests ==2.7.0',
    'flake8'
]

description = """
Tool for cleaning up old snapshots from a docker registry
"""

setup(
    name='dreg-cleaner',
    version='0.1-SNAPSHOT',
    description=description,
    author='Eric Diven',
    author_email='ebd2-github a) gmail.com',
    keywords='docker registry',
    url='https://github.com/ebd2/dreg-cleaner',
    packages=find_packages(),
    package_dir={'dreg-cleaner': 'dreg-cleaner'},
    install_requires=requirements,
    entry_points={'console_scripts': ['dreg-cleaner = dreg_cleaner.main:main']}
)
