import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="itanium_demangler",
    version="0.0.1",
    author="whitequark",
    author_email="whitequark@whitequark.org",
    description="Pure Python parser for mangled itanium symbols",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/whitequark/python-itanium_demangler",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2",
        "Operating System :: OS Independent",
    ],
)