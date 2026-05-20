import subprocess as sp
from pathlib import Path


class Config:
    __slots__ = ["repo", "name", "branch"]

    def __init__(self, repo: str, name: str, branch: str, /) -> None:
        self.repo: str = repo
        self.name: str = name
        self.branch: str = branch

    def __repr__(self) -> str:
        return f"Config(repo={self.repo}, name={self.name}, branch={self.branch})"

    def clean(self) -> int:
        if not self.folder().exists():
            return 0
        return sp.check_call(["rm", "-rf", self.folder()])

    def clone(self) -> int:
        return sp.check_call(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "-b",
                self.branch,
                self.repo,
                self.folder(),
            ],
            stdout=sp.DEVNULL,
            stderr=sp.DEVNULL,
        )

    def setup(self) -> str:
        self.clean()
        self.clone()
        return str(self.folder())

    def folder(self) -> Path:
        return Path("thirdparty") / self.name


REPOS: list[Config] = [
    # five mainstream repos
    Config("https://github.com/SagerNet/sing-box.git", "sing-box", "stable"),
    Config("https://github.com/v2ray/v2ray-core.git", "v2ray-core", "master"),
    Config("https://github.com/XTLS/Xray-core.git", "Xray-core", "main"),
    Config("https://github.com/yaling888/quirktiva.git", "quirktiva", "plus"),
    Config("https://github.com/MetaCubeX/mihomo.git", "mihomo", "Alpha"),
    # client libraries and apps
    # - Go based
    Config("https://github.com/apernet/hysteria.git", "hysteria-legacy-v1", "hy1"),
    Config("https://github.com/apernet/hysteria.git", "hysteria", "master"),
    Config("https://github.com/XTLS/REALITY.git", "REALITY", "main"),
    Config("https://github.com/anytls/anytls-go.git", "anytls-go", "main"),
    Config("https://github.com/trojan-gfw/trojan.git", "trojan", "master"),
    Config(
        "https://github.com/shadowsocks/go-shadowsocks2.git",
        "go-shadowsocks2",
        "master",
    ),
    Config("https://github.com/WireGuard/wireguard-go.git", "wireguard-go", "master"),
    Config("https://github.com/nullroute1970/StormDNS.git", "StormDNS", "main"),
    # - C/C++ based
    Config("https://github.com/tindy2013/subconverter.git", "subconverter", "master"),
    # - Rust based
    Config("https://github.com/zhangsan946/jets", "jets", "main"),
    Config("https://github.com/jxo-me/anytls-rs.git", "anytls-rs", "main"),
    Config("https://github.com/eycorsican/leaf.git", "leaf", "master"),
    Config("https://github.com/cfal/shoes.git", "shoes", "master"),
    Config("https://github.com/radioactiveAHM/ray", "ray", "main"),
    Config("https://github.com/cty123/TrojanRust.git", "TrojanRust", "main"),
    Config(
        "https://github.com/shadowsocks/shadowsocks-rust.git",
        "shadowsocks-rust",
        "master",
    ),
    # - C# based
    Config("https://github.com/2dust/v2rayN.git", "v2rayN", "master"),
    # parsers and aggregators for subscription files
    Config("https://github.com/kutovoys/xray-checker.git", "xray-checker", "main"),
    Config(
        "https://github.com/AvenCores/goida-vpn-configs.git",
        "goida-vpn-configs",
        "main",
    ),
    Config(
        "https://github.com/Epodonios/v2ray-configs.git",
        "v2ray-configs",
        "main",
    ),
    Config(
        "https://github.com/wuqb2i4f/xray-config-toolkit.git",
        "xray-config-toolkit",
        "main",
    ),
    # examples for reference
    Config(
        "https://github.com/DNSCrypt/encrypted-dns-server.git",
        "encrypted-dns-server",
        "master",
    ),
    Config("https://github.com/0x676e67/wreq-util.git", "wreq-util", "main"),
    Config("https://github.com/refraction-networking/utls.git", "utls", "master"),
]


def main():
    from concurrent.futures import ProcessPoolExecutor

    ppe = ProcessPoolExecutor(max_workers=8)

    for done in ppe.map(Config.setup, REPOS):
        print(f"- [v] {done}")


if __name__ == "__main__":
    main()
