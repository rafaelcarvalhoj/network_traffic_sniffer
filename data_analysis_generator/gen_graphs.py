import os

if not os.path.exists("analisys.ipynb"):
    print("Canot open analisys.ipynb")
    exit(1)

os.system("jupyter nbconvert --to notebook --execute analisys.ipynb")

os.system("rm analisys.nbconvert.ipynb")
