import json
import os
import subprocess
import sys

PAYLOAD_ENV = os.getenv("PAYLOAD")


def get_string_between(o_string, start, end):
    if start in o_string and end in o_string:
        s = o_string.index(start) + len(start)
        e = o_string.index(end, s)
        return o_string[s:e]
    exit(1)


def create_fingerprint(name):
    yaml_data = get_string_between(ISSUE_BODY, "```yaml", "```").strip()
    test_file_path = "web_fingerprint/" + name + ".yaml"
    with open(test_file_path, "w") as y:
        y.write(yaml_data)


def run_observer_ward(name):
    test_file_path = "web_fingerprint/" + name + ".yaml"
    target = get_string_between(ISSUE_BODY, "### 测试目标", "### 指纹的Yaml").strip()
    observer_ward = os.path.expanduser("~") + '/.config/observer_ward/observer_ward_amd64'
    proc = subprocess.Popen(args=[observer_ward, "-t", target,
                                  "--verify", test_file_path, "--silent"], shell=False, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        outs, errs = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        outs, errs = proc.communicate()
    if errs:
        exit(1)
    else:
        print(outs.decode())


ACTION = None
FINGERPRINT_NAME = None
FUNC = None
LABEL = None
PAYLOAD = json.loads(PAYLOAD_ENV)
issue = PAYLOAD.get("issue", {})
ISSUE_BODY = issue.get("body", "")
ISSUE_LABELS = issue.get("labels", [])
ISSUE_TITLE = issue.get("title", "")
ISSUE_STAT = issue.get("state", "open")
ISSUE_USER_LOGIN = issue.get("user", {}).get("login")
if "[" in ISSUE_TITLE and "]" in ISSUE_TITLE:
    FINGERPRINT_NAME = get_string_between(ISSUE_TITLE, "[", "]")
if "提交指纹" in ISSUE_TITLE:
    FUNC = getattr(sys.modules[__name__], "create_fingerprint")
elif "修改指纹" in ISSUE_TITLE:
    FUNC = getattr(sys.modules[__name__], "create_fingerprint")
elif "删除指纹" in ISSUE_TITLE:
    FUNC = getattr(sys.modules[__name__], "create_fingerprint")
ACTION = PAYLOAD.get("action")
LABEL = PAYLOAD.get("label", {}).get("name")
SENDER = PAYLOAD.get("sender", {}).get("login", "")


def runner():
    if ACTION == "edited" or ACTION == "opened":  # 编辑标题或者内容，根据标题关键词判断功能：提交指纹，修改指纹，删除指纹
        FUNC(FINGERPRINT_NAME)
        run_observer_ward(FINGERPRINT_NAME)
    elif ACTION == "closed":  # 关闭ISSUE，合并或者不符合格式的
        pass
    elif ACTION == "labeled":  # 打标签，已经测试，已经审核,判断发起人，不是管理员取消标签
        if LABEL == "Reviewed" and SENDER == "cn-kali-team":
            FUNC(FINGERPRINT_NAME)
    elif ACTION == "unlabeled":  # 取消标签，测试完了，取消待测试标签，审核完了取消待审核标签
        pass
    elif ACTION == "assigned":  # 分配，分配给cn-kali-team或者其他管理员
        pass
    elif ACTION == "unassigned":  # 取消分配
        pass
    else:
        # exit(1)
        pass


if __name__ == '__main__':
    runner()
