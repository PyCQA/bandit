import random
import os
import somelib

bad = random.Random()
bad = random.random()
bad = random.randrange()
bad = random.randint()
bad = random.choice()
bad = random.choices()
bad = random.uniform()
bad = random.triangular()

good = os.urandom()
good = random.SystemRandom()

unknown = random()
unknown = somelib.a.random()
