import pickle as pkl
from net_vec.vector import Unit

with open("statistics.pkl", "rb") as f:
    x_list = pkl.load(f)
    feature_list = pkl.load(f)
    all_feature_list = pkl.load(f)
    glob_dis_list = pkl.load(f)
    avg_dis_list = pkl.load(f)

print(x_list)
print(feature_list)
print(all_feature_list)
print(glob_dis_list)
print(avg_dis_list)