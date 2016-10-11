from setuptools import setup, find_packages

requirements = [
    'requests ==2.7.0'
]

setup_requirements = [
    'flake8'
]

description = """
Tool for interacting with the Docker Registry API version 2.
"""

setup(
    name='docker-reg-api-v2',
    version='0.1-SNAPSHOT',
    description=description,
    author='Eric Diven',
    author_email='ebd2-github a) gmail.com',
    keywords='docker resgistry',
    url='https://github.com/ebd2/docker-reg-api-v2',
    packages=find_packages(),
    package_dir={'docker_reg_api_v2': 'docker_reg_api_v2'},
    install_requires=requirements,
    setup_requires=setup_requirements,
    entry_points={'console_scripts': ['docker-reg = docker_reg_api_v2.main:main']}
)
