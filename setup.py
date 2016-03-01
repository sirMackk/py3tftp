from setuptools import setup
from py3tftp import __version__


def readme():
    with open('README.md') as f:
        return f.read()


setup(
    name='py3tftp',
    version=__version__,
    description='Python 3 asynchronous TFTP server.',
    long_description=readme(),
    url='http://github.com/sirMackk/py3tftp',
    author='Matt Obarzanek',
    author_email='matt@mattscodecave.com',
    license='MIT',
    keywords='async asynchronous tftp',
    packages=['py3tftp'],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'py3tftp = py3tftp.__main__:main'
        ]
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.5',
        'Topic :: Utilities',
        'Topic :: Software Development',
        'License :: OSI Approved :: MIT License',
    ],
)
