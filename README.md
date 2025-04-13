# Video Instructions #

We made a video to explain how to run the server with visual aid.

VIDEO: https://www.youtube.com/watch?v=h0zn5FVsZYM


# Text Instructions #

Before running, make sure to create a virtual environment using python's virtual environment package. On windows, this can be installed using:

`python -m venv venv`

Once this is done, the virtual environment can be activated using

`venv\scripts\activate.bat`

Once the virtual environment is activated, you should see `(venv)` in your terminal. Then you can install all needed libraries by typing

`pip install -r requirements.txt`

in the terminal and hitting enter. All needed libraries should be installed.

## Server Usage ##
Use `python server.py` in the path `ratchat/server' to start the server. It will start on 127.0.0.1:8000. It will also create .json files wherever you run it from.


## Client Usage ##
`client.py` is the client program. You can run it with 'python client.py --port [port]`. It will create .json files specific to each individual client, so it is recommended you run it from the 'bob' and 'alice' directories provided.

Note that the clients need to be run on seperate ports from each other and the server, otherwise conflicts will happen!

## Other Notes ##
This is a prototype, and not meant for serious messaging. As such, bugs may occur under certain circumstances such as making multiple of the same user, using the same phone number, network errors, etc.

If issues occur, it can be reset by deleting all the generated .json files.

## Authors ##
Made for Cryptography 418 at UCalgary during the Winter 2025 semester.
Written by Jaxon Sloan, Sidd Pai, Ethan Oke and George Vassilev.
