from setuptools import setup, find_packages

setup(
    name='ddos_detection_tool',
    version='0.1',
    packages=find_packages(),
    install_requires=[
    ],
    entry_points={
        'console_scripts': [
            'ddos_detection_app = ddos_detection_tool.gui.ddos_detection_app:main',
        ],
    },
)