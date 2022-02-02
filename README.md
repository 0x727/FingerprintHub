# FingerprintHub

郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。

- 该仓库为侦查守卫(ObserverWard)指纹库，[ObserverWard](https://github.com/0x727/ObserverWard_0x727)是一个基于社区的指纹识别工具。

| 类别 | 说明                                                         |
| ---- | ------------------------------------------------------------ |
| 作者 | [三米前有蕉皮](https://github.com/cn-kali-team)              |
| 团队 | [0x727](https://github.com/0x727) 未来一段时间将陆续开源工具 |
| 定位 | 社区化指纹库，让管理和使用指纹规则更加简单。                 |
| 语言 | Yaml                                                         |
| 功能 | 可自定义请求，使用github actions 自动更新指纹库。            |

## 规则说明

```yaml
name: apache-shiro
priority: 3
nuclei_tags:
  - - "shiro"
    - "apache"
fingerprint:
  - path: /
    request_method: post
    request_headers:
      Cookie: rememberMe=admin;rememberMe-K=admin
    request_data: ''
    status_code: 0
    headers:
      Set-Cookie: rememberMe=deleteMe
    keyword: [ ]
    favicon_hash: [ ]
  - path: /
    request_method: get
    request_headers: { }
    request_data: ''
    status_code: 0
    headers: { }
    keyword:
      - </i> shiro</li>
    favicon_hash: [ ]
```

| 字段            | 数据类型               | 描述                                                         |
| --------------- | ---------------------- | ------------------------------------------------------------ |
| request_method  | String                 | 自定义请求方法                                               |
| request_data    | String                 | 自定义请求数据，base64编码后的字符串                         |
| request_headers | HashMap<String,String> | 自定义请求头                                                 |
| path            | String                 | HTTP请求的路径。                                             |
| status_code     | u32                    | 响应状态码，不匹配可以填0                                    |
| headers         | HashMap<String,String> | 相应的请求头，以键值对出现，值填`*`时只匹配键                |
| keyword         | Vec<String>            | 响应的HTML关键词数组，可以添加多个关键词提高识别精度         |
| favicon_hash    | Vec<String>            | favicon的MD5哈希数组，取并集关系，只要匹配到一个就算识别到   |
| priority        | u32                    | 优先程度，用来排序是否为重要组件资产，数字越大越重要，可选：[1,2,3]，有标题和存在漏洞都会+1 |
| nuclei_tags     | Vec<Vec<String>>       | nuclei中的标签，当标签为[["shiro","apache"]]的时候，<br>yaml中同时有`shiro`，`apache`这两个标签会被分到`apache-shiro`这个文件夹 |

- 一个`path`为一组指纹，像上面的yaml规则中有两组指纹，只要匹配到了一组，就会返回`name`字段，也就是`apache-shiro`。

## 如何贡献

### 验证单个指纹是否有效

- 为了方便验证编写的yaml规则是否有效，可以使用`--verify`参数指定要验证的yaml文件，`-t`指定测试目标对指纹进行验证。

```bash
➜  ~ ./observer_ward_amd64 --verify 0x727/FingerprintHub/fingerprint/swagger.yaml -t http://httpbin.org
[ http://httpbin.org |["swagger"] | 9593 | 200 | httpbin.org ]
Important technology:

+--------------------+---------+--------+-------------+-------------+----------+
| url                | name    | length | status_code | title       | priority |
+====================+=========+========+=============+=============+==========+
| http://httpbin.org | swagger | 9593   | 200         | httpbin.org | 5        |
+--------------------+---------+--------+-------------+-------------+----------+
```

### 提交指纹规则

- 点击Fork按钮克隆这个项目到你的仓库

```bash
git clone git@github.com:你的个人github用户名/FingerprintHub.git
```

- 添加上游接收更新

```bash
cd FingerprintHub
git remote add upstream git@github.com:0x727/FingerprintHub.git
git fetch upstream
```

- 配置你的github个人信息

```bash
git config --global user.name "$GITHUB_USERNAME"
git config --global user.email "$GITHUB_EMAIL"
git config --global github.user "$GITHUB_USERNAME"
```

- 拉取所有分支的规则

```bash
git fetch --all
git fetch upstream
```

- **不要**直接在`main`分支上修改，例如我想添加一个`thinkphp`的指纹，创建一个新的分支并切换到新的分支。

```bash
git checkout -b thinkphp
```

- 复制一份指纹规则文件，修改文件名和你想要提交的组件名一样，修改yaml文件里面的`name`字段为添加的组件名，添加或者修改规则。
- 跟踪修改和提交Pull-Requests，合并指纹。

```
git add 你添加或者修改的文件名
git commit -m "添加的组件名或者你的描述"
git push origin thinkphp
```

- 打开你Fork这个项目的地址，点击与上游合并，等待审核合并指纹。

### 谁在使用FingerprintHub
- 如果你的开源工具中也使用了`FingerprintHub`，我感到非常的荣幸，欢迎补充列表，当项目有破坏性更新时可以及时通知到你。

| [ObserverWard](https://github.com/0x727/ObserverWard_0x727) |
| ----------------------------------------------------------- |
| [nuclei](https://github.com/projectdiscovery/nuclei)        |
| [nemo_go](https://github.com/hanc00l/nemo_go)               |

### 指纹反馈

- 当前指纹库收集于互联网，虽然已经经过了人工整理，但是难免会有以下情况：
    - 出现误报，当指纹不够精确时会产生识别不准确的情况。
    - 组件重复，可能出现多个组件名称，但是都是同一个组件。
    - 识别不出组件，指纹规则覆盖不到。
- 出现上面情况可以提交**issues**，可以附上演示URL地址，如果不方便演示可以提交首页的HTML源码，我们会人工修正指纹规则。

### 谢谢

- 感谢您的关注和支持！
