printf "Create and install venv"
mkdir venv && python3 -m venv venv && venv/bin/python3 -m pip install -r requirements.txt && printf "Venv is installed"

printf "Don't forgot to create .env for this example:\n\nhost=<>\nusername=<>\npassword=<>\nsecret=<>"
