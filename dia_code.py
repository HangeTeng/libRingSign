from diagrams import Diagram, Cluster, Edge
from diagrams.generic.blank import Blank
from diagrams.generic.storage import Storage

graph_attrs = {
    "fontsize": "20",           # 设置全局字体大小
    "fontcolor": "black",        # 设置全局字体颜色
    "labelloc": "t",             # 标签位置
    "labeljust": "c",            # 标签对齐
}

edge_attrs = {
    "color": "gray",             # 默认边线颜色
    "penwidth": "2.0",           # 边线粗细
    "fontcolor": "blue",         # 边上文字颜色
    "fontsize": "14"             # 边上文字大小
}

with Diagram("Enhanced Sign Test Flow with Core Config Interaction", show=False, graph_attr=graph_attrs):
    # 配置模块
    config = Blank("Config Definitions")
    
    # KeyGenerator 流程
    with Cluster("KeyGenerator"):
        keygen_init = Blank("Initialize")
        save_config = Blank("SaveConfig")
        generate_sign_key = Blank("GenerateSignKey")

        # KeyGenerator 的调用关系
        keygen_init >> Edge(label="initialize", **edge_attrs) >> save_config
        keygen_init >> Edge(label="generate key", **edge_attrs) >> generate_sign_key

    # 哈希模块
    with Cluster("Hash"):
        hash_class = Blank("Hash")
        hash_to_bn = Blank("hashToBn")

        # 哈希模块的调用关系
        hash_class >> Edge(label="compute hash", **edge_attrs) >> hash_to_bn

    # 消息与事件初始化
    msg_event = Blank("Initialize Message and Event")

    # Signer 流程
    with Cluster("Signer Process"):
        signers = []
        for i in range(1, 4):  # 三个签名者示例
            with Cluster(f"Signer {i}"):
                signer_init = Blank("Initialize")
                partial_key_gen = Blank("GeneratePartialKey")
                generate_full_key = Blank("GenerateFullKey")
                sign_message = Blank("Sign")
                verify_signature = Blank("Verify")

                # Signer 内部调用关系
                signer_init >> Edge(label="partial key", **edge_attrs) >> partial_key_gen
                partial_key_gen >> Edge(label="full key", **edge_attrs) >> generate_full_key
                generate_full_key >> Edge(label="sign", **edge_attrs) >> sign_message >> Edge(label="verify", **edge_attrs) >> verify_signature

                signers.append((signer_init, partial_key_gen, generate_full_key, sign_message, verify_signature))

    # config 文件夹
    with Cluster("Config Folder"):
        system_config = Storage("system_config.json")
        system_key = Storage("system_key.json")

    # 环签名生成和验证
    ring_sign = Blank("Generate Ring Signature")
    verify_sign = Blank("Verify Signature")

    # 配置和 KeyGenerator 的连接
    config >> Edge(label="default settings", **edge_attrs) >> keygen_init >> save_config
    keygen_init >> Edge(label="generate system keys", **edge_attrs) >> generate_sign_key

    # KeyGenerator 与 config 文件夹交互
    save_config >> Edge(label="save system config", color="blue", penwidth="2.0", fontcolor="darkblue") >> system_config
    generate_sign_key >> Edge(label="save system keys", color="blue", penwidth="2.0", fontcolor="darkblue") >> system_key

    # Signer 与 config 文件夹交互
    for signer_init, partial_key_gen, generate_full_key, sign_message, verify_signature in signers:
        msg_event >> Edge(label="setup", color="purple", penwidth="2.0", fontcolor="purple") >> signer_init
        partial_key_gen >> Edge(label="request system keys", **edge_attrs) >> generate_sign_key
        generate_sign_key >> Edge(label="provide keys", **edge_attrs) >> generate_full_key
        sign_message >> ring_sign

    # 环签名生成和验证
    ring_sign >> Edge(label="generate and verify", color="green", penwidth="2.0", fontcolor="green") >> verify_sign

    # Hash 模块调用关系
    generate_sign_key >> Edge(label="generate ID hash", **edge_attrs) >> hash_to_bn
    sign_message >> Edge(label="generate h_i, a_i", **edge_attrs) >> hash_to_bn
    verify_signature >> Edge(label="verify h_i, a_i", **edge_attrs) >> hash_to_bn
