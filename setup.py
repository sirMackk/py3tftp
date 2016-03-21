from setuptools import setup
from py3tftp import __version__

try:
    import pypandoc
except ImportError:
    pypandoc = None


def readme():
    with open('README.md', 'r') as f:
        readme_md = f.read()
        if pypandoc:
            readme_rst = pypandoc.convert(readme_md, 'rst', format='md')
            return readme_rst
        else:
            return readme_md


setup(
    name='py3tftp',
    version=__version__,
    description='Python 3 asynchronous TFTP server.',
    long_description=readme(),
    url='http://github.com/sirMackk/py3tftp',
    author='Matt O.',
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
