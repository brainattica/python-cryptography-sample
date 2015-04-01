# Brainattica & Cryptography. The Python library Sample.

This repo make reference to a post in our blog [http://www.brainattica.com/blog]

## Usage
You can clone it and play a little bit with code as following:

1. Create a virtualenv with virtualenvwrapper:
	```
	mkvirtualenv <your_path> --python=/usr/bin/python3 brainattica_cryptography
	workon brainattica_cryptography
	```
2. Install Cryprography.

	In Ubuntu:
	```
	$ sudo apt-get install build-essential libssl-dev libffi-dev python-dev
	$ pip install cryptography
	```
	See installation instructions in [https://cryptography.io/en/latest/installation/] for more information.
3. Execute sample:
	```
	python sample.py 
	```
	You should get the following message if all is right: 
	> I get it!!
4. You can execute test as well.
	```
	python test_brain_cryptography.py
	``
	You should get:
	> Ran 6 tests in _. OK.


