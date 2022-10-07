# Password Checker

Simple script to check if your passwords have been leaked on the Internet

## Usage

```
python check.py -p password1 [password2 [password3 [...]]]
```

#### Example:

```
python check.py -p hello bye 123 ultrasupersafepasswordthatno0newillevergue$$
```

```
he***
        🔴264149 leaks. You should change it.
by*
        🔴1365 leaks. You should change it.
12*
        🔴196 leaks. You should change it.
ul********************************************
        ✅ No leaks found!

```

## Installation

```
pip install -r requirements.txt
```
