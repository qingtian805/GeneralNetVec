import pickle as pkl
from net_vec.vector import Unit

with open("statistics.pkl", "rb") as f:
    x_list = pkl.load(f)
    feature_list = pkl.load(f)
    all_feature_list = pkl.load(f)
    glob_dis_list = pkl.load(f)
    avg_dis_list = pkl.load(f)

print(glob_dis_list[2])
print(avg_dis_list[2])
# print(x_list[0].mal[0][0])
# print(x_list[1].mal[0][0])