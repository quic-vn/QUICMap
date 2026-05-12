import pandas as pd

df = pd.read_csv("ipv6/vn_ipv6_quic_results_2.csv")

targets = df[df["success"] == 1]["saddr"]

with open("ipv6_list.txt", "w") as f:
    for ip in targets:
        f.write(f"{ip}\n")