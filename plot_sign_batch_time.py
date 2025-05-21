import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from matplotlib.font_manager import FontProperties
import matplotlib as mpl
import os
from result import results

# === 字体路径配置（可根据系统调整） ===
zh_font_path = "C:/Users/HangeTeng/AppData/Local/Microsoft/Windows/Fonts/SimSun.ttf"        # 宋体
en_font_path = "C:/Windows/Fonts/times.ttf"         # Times New Roman

if not os.path.exists(zh_font_path):
    raise FileNotFoundError(f"找不到宋体字体文件: {zh_font_path}")
if not os.path.exists(en_font_path):
    raise FileNotFoundError(f"找不到 Times New Roman 字体文件: {en_font_path}")

# 加载字体对象
zh_font = FontProperties(fname=zh_font_path, size=14)
en_font = FontProperties(fname=en_font_path, size=14)
en_font_tick = FontProperties(fname=en_font_path, size=12)  # 坐标轴刻度专用

# === 准备数据 ===
x = sorted(results.keys())
keygen_times = [results[n]['keygen_ms'] / 1000 for n in x]
sign_times = [results[n]['sign_ms'] / 1000 for n in x]

# === 绘图 ===
plt.figure(figsize=(6, 4))

# 图例中文+英文补充
label_keygen = "密钥生成时间（Keygen，单位：秒）"
label_sign = "签名时间（Sign，单位：秒）"

plt.plot(
    x, keygen_times,
    marker='o', linestyle='-', color='#1f77b4',
    label=label_keygen, markerfacecolor='white'
)
plt.plot(
    x, sign_times,
    marker='^', linestyle='-', color='#ff7f0e',
    label=label_sign, markerfacecolor='white'
)

# === 注释点（n=500）===
mid_idx = x.index(500)
x_point = x[mid_idx]
y_k = keygen_times[mid_idx]
y_s = sign_times[mid_idx]

plt.annotate(
    f"参与者: {x_point}人\nKeygen: {y_k:.1f}s\nSign: {y_s:.1f}s",
    xy=(x_point, y_s),
    xytext=(-10, 35),
    textcoords='offset points',
    arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=.2"),
    fontsize=12,
    fontproperties=zh_font
)

# === 设置坐标轴标签 ===
plt.xlabel("参与者数量", fontsize=16, fontweight='bold', fontproperties=zh_font)
plt.ylabel("运行时间（秒）", fontsize=16, fontweight='bold', fontproperties=zh_font)

# === 设置坐标轴刻度字体为 Times New Roman ===
plt.xticks(fontproperties=en_font_tick)
plt.yticks(fontproperties=en_font_tick)

plt.tick_params(axis='both', which='major', labelsize=12)
plt.grid(which='both', linestyle='--', linewidth=0.5)
plt.gca().yaxis.set_major_locator(MaxNLocator(nbins='auto'))

# === 图例 ===
plt.legend(loc='upper left', prop=zh_font)

plt.tight_layout()
plt.savefig("plot_sign_batch_time_full_tnr.pdf")
plt.show()