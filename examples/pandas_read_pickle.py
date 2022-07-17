import pickle
import pandas as pd


df = pd.DataFrame(
    {
        "col_A": [1, 2]
    }
)
pick = pickle.dumps(df)

print(pd.read_pickle(pick))
