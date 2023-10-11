## 简介

**注意：clash内核无法使用这些节点，你要用clashmeta**

## 为什么要套上warp
<details>
  <summary>点击展开/折叠</summary>
首先chromego屏蔽了很多网站，包括你喜欢的p开头的网站，套上warp可以突破这一层限制。

第二我并不喜欢使用机场等服务，原因就是机场主或者节点主完全知道你访问的网站，虽然有一层https加密，但是他们还是可以知道你访问的域名已经你连接的时间，套上warp之后，他们只能看到一串加密流量。

第三，我为什么要提取节点出来，不仅仅是因为方便管理，可以在一个配置文件中切换不同的节点。而且是因为我并不喜欢使用他们所提供的客户端，虽然chromego所提供的客户端并没有什么问题，但是我还是喜欢自己常用的客户端。

</details>

## 如何修改为自己的warp节点
可以用warp+机器人和提取wg节点替换掉配置文件中的wg信息
[warp提取wireguard网站](https://replit.com/@misaka-blog/wgcf-profile-generator)
[warp+机器人](https://t.me/generatewarpplusbot)

## 订阅链接分享(无需翻墙版-托管自netlify）
### 不套warp版本（clashmeta-全平台通用-节点最全）
**不含hysteria2节点**
```
https://mareep.netlify.app/sub/merged_proxies.yaml
```
**含hysteria2节点(节点最全）**
```
https://mareep.netlify.app/sub/merged_proxies_new.yaml
```
### 套warp版本（clashmeta-全平台通用-节点最全)
**不含hysteria2节点**
```
https://mareep.netlify.app/sub/merged_warp_proxies.yaml
```
**含hysteria2节点(节点最全）**
```
https://mareep.netlify.app/sub/merged_warp_proxies_new.yaml
```
### 通用链接 shadowrocket-nekoray
```
https://mareep.netlify.app/sub/shadowrocket_base64.txt
```

## 订阅链接分享（需要翻墙版-托管自github）
<details>
  <summary>点击展开/折叠</summary>
  
### 不套warp版本（clashmeta
```
https://raw.githubusercontent.com/vveg26/chromego_merge/main/sub/merged_proxies.yaml
```
### 套warp版本（clashmeta
```
https://raw.githubusercontent.com/vveg26/chromego_merge/main/sub/merged_warp_proxies.yaml
```
### 通用链接 shadowrocket-nekoray
```
https://raw.githubusercontent.com/vveg26/chromego_merge/main/sub/shadowrocket_base64.txt
```

</details>


## 致谢
[Alvin9999](https://github.com/Alvin9999/pac2/tree/master)

## TODO
- 部分代码逻辑不够优雅
- sing-box节点的处理
- xray部分节点的处理
- 融合ss和ssr


