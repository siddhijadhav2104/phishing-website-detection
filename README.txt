PHISHING WEBSITE DETECTION USING MACHINE LEARNING
====================================================

This package is designed so you can EXTRACT ONE FOLDER and open it.

QUICK START (Windows)
---------------------
1. Install Python 3.11 or 3.12:
   https://www.python.org/downloads/
   During installation, tick "Add Python to PATH".

2. Install Node.js LTS:
   https://nodejs.org/

3. Optional but recommended for scan history:
   Install MongoDB Community Server.
   The project still runs without MongoDB; predictions work and history is stored in a local JSON fallback.

4. Double-click:
      START_PROJECT.bat

The launcher will:
- create the Python virtual environment
- install backend packages
- train/create the ML model if required
- install frontend packages
- start Flask and React
- open the website automatically

Then use:
   http://localhost:5173

STOPPING THE PROJECT
--------------------
Close the launcher window or press Ctrl+C.

PROJECT STACK
-------------
Frontend : React 19, Vite, Bootstrap 5
Backend  : Python 3.12, Flask, Flask-CORS
ML       : Scikit-learn Random Forest
Database : MongoDB (optional; JSON fallback included)
