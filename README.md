# FingerprintHub

郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。

- 侦查守卫(ObserverWard)指纹库，ObserverWard是一个基于社区的指纹识别工具。

## 规则说明

```yaml
name: swagger
fingerprint:
- path: /
  status_code: 0
  headers: {}
  keyword:
  - Swagger UI
  favicon_hash: []
  priority: 3
- path: /
  status_code: 0
  headers: {}
  keyword:
  - swagger-ui.css
  favicon_hash: []
  priority: 2
- path: /
  status_code: 0
  headers: {}
  keyword:
  - swagger-ui.js
  favicon_hash: []
  priority: 2
```

| 字段         | 数据类型               | 描述                                                         |
| ------------ | ---------------------- | ------------------------------------------------------------ |
| path         | String                 | HTTP请求的路径                                               |
| status_code  | u32                    | 响应状态码，不匹配可以填0                                    |
| headers      | HashMap<String,String> | 相应的请求头，以键值对出现                                   |
| keyword      | Vec<String>            | 响应的HTML关键词数组，可以添加多个提高识别精度               |
| favicon_hash | HashSet<String>        | 网页图标的MD5或者MMH3哈希，会与响应中的哈希取并集            |
| priority     | u32                    | 优先程度，用来排序是否为重要组件资产，数字越大越重要，可选：1，2，3 |

- 一个`path`为一组指纹，像上面的yaml规则中有三组指纹，只要匹配到了一组，就会返回`name`字段，也就是`swagger`。

## 如何贡献

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
git checkout -b upstream-main --track upstream/main
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

- **不要**直接在`main`分支上修改，创建一个新的分支并切换到新的分支。

```bash
git checkout -b thinkphp
```

- 复制一份指纹规则文件，修改文件名和你想要提交的组件名一样，修改yaml文件里面的`name`字段为添加的组件名，添加或者修改规则。
- 跟踪修改和提交Pull-Requests，合并指纹。

```
git add 你添加的文件名
git commit -m "添加的组件名或者你的描述"
git push origin thinkphp
```

- 打开你Fork这个项目的地址，点击与上游合并，等待审核合并指纹。

### 指纹反馈

- 当前指纹库收集于互联网，虽然已经经过了人工整理，但是难免会有以下情况：
  - 出现误报，当指纹不够精确时会产生识别不准确的情况。
  - 组件重复，可能出现多个组件名称，但是都是同一个组件。
  - 识别不出组件，指纹规则覆盖不到。
- 出现上面情况可以提交**issues**，可以附上演示URL地址，如果不方便演示可以提交首页的HTML源码，我们会人工修正指纹规则。

### 谢谢

- 感谢您的关注和支持！
