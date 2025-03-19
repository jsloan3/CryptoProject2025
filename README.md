# Instructions #

Before running, make sure to create a virtual environment using python's virtual environment package. On windows, this can be installed using:

`python -m venv venv`

Once this is done, the virtual environment can be activated using

`venv\scripts\activate.bat`

Once the virtual environment is activated, you should see `(venv)` in your terminal. Then you can install all needed libraries by typing

`pip install -r requirements.txt`

in the terminal and hitting enter. All needed libraries should be installed.


## Server Usage ##
Use `python main.py` to start the server. It will start on 127.0.0.1:5000 by default.

Use `python seed.py` to create the main.db file with the proper table.

`testclient.py` is a showcase on how POST requests work. Running it while the server is online will insert a new user into main.db with the info sent through a POST request. I recommend an extension like `SQLite Viewer` to inspect the .db file easily (make sure to refresh it to see the latest changes).

## Key Generation and Storage ##
To generate your private key (which is encrypted) and store it on your computer, make sure to set RATCHET_KEY_PATH (environment variable) to the folder/path where you want to store your keys.

Then, use `python keygen.py` to generate and store your keys. The keys will automatically be stored in your `RATCHET_KEY_PATH` directory.

Once your keys are stored, you can run `testclient.py` to test the clients public key being stored on the server database.