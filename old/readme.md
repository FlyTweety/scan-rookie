only tested on linux for now

```
sudo su
python3 Main.py
```



Make sure you have Python 3. Do the following from the command line:

```
$ git clone https://github.com/noise-lab/iot-inspector-client.git
$ cd iot-inspector-client/src
$ sudo su # Make sure that everything below is run as root
$ python3 -m venv env
$ source env/bin/activate
$ pip install -r requirements.txt
$ python3 start_inspector.py
```
