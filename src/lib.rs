#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    reason = "For AI agent context reduction"
)]
#![warn(clippy::nursery)]
pub mod db;
mod error;
pub mod mining;
mod utils;

pub mod urlx;

use rustc_hash::FxHashSet;
use std::borrow::Cow;

use base64::Engine;
use bstr::ByteSlice;
// restrict to crate internal usage
pub(crate) use error::{CutResult, NomError, RawResult, Span};

use std::io::Write;
pub(crate) use utils::{
    norm_extras::normalize_extras, permissive_json::permissive_json, unescaper::Unescaper,
};
// exported

pub use urlx::{SchemeX, UrlX};
pub use utils::line::{Line, Lines};

pub(crate) use urlx::{HostSpec, PortDecl, PortSpec};

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod macros {
    #![allow(unused_macros)]

    macro_rules! nom_bail {
        ($input: expr, $code: ident) => {{
            return Err(nom::Err::Error(nom::error::Error::new(
                $input,
                nom::error::ErrorKind::$code,
            )));
        }};

        ($input: expr, $code: ident, $context: expr) => {{
            return Err(::nom::Err::Error(crate::Error {
                row: $input.location_line(),
                col: $input.get_utf8_column() as u32,
                offset: $input.location_offset(),
                length: $input.len(),
                // XXX: Default value for errors without a tag
                errtag: $code,
                errctx: $context,
            }));
        }};
    }

    pub(crate) use nom_bail;
}

pub(crate) use macros::nom_bail;

use crate::utils::line::Data;

pub fn parse_sub(url: &url::Url, sub: &[u8]) -> Lines<'static> {
    let sub = sub.trim_end_with(|c| c.is_whitespace() || c == '=');
    let sub = base64::prelude::BASE64_STANDARD_NO_PAD
        .decode(sub)
        .map_err(|_| tracing::info!("Not a Standard Base64"))
        .or_else(|_| {
            base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(sub)
                .map_err(|_| tracing::info!("Not a URL Safe Base64"))
        })
        .map_or_else(|_| Cow::Borrowed(sub), Cow::Owned);

    tracing::info!("Total length of incoming data: {}", sub.len());

    let sub = normalize_extras(sub.as_ref());
    if let Cow::Owned(_) = sub {
        tracing::info!("Some extras was fixed")
    }
    let sub = String::from_utf8_lossy(sub.as_ref());
    if let Cow::Owned(_) = sub {
        tracing::info!("Some characters was replaced")
    }

    Lines::new_raw(url, sub.as_ref()).processed()
}

pub async fn download_sub<W: Write>(
    url: url::Url,
    dest: &mut W,
    unique: &mut Option<FxHashSet<u64>>,
) -> std::io::Result<()> {
    let proxies = download_sub_proxies(url).await?;
    let entries = unique.get_or_insert_default();
    let before = entries.len();
    for urlx in proxies {
        if entries.insert(urlx.uid) {
            writeln!(dest, "{urlx}").unwrap();
        }
    }
    let after = entries.len();
    tracing::info!("New entries: {}", after - before);
    Ok(())
}

pub async fn download_sub_proxies(url: url::Url) -> std::io::Result<Vec<UrlX>> {
    let client = reqwest::Client::builder()
        .user_agent("Xray-Rs/0.1.0")
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;

    let t = if matches!(
        url.host_str(),
        Some("raw.githubusercontent.com" | "github.com")
    ) && let Ok(auth) = std::env::var("GITHUB_TOKEN")
    {
        client.get(url.as_str()).bearer_auth(auth)
    } else {
        client.get(url.as_str())
    };
    let t = t
        .send()
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?
        .error_for_status()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;

    tracing::info!("Downloading {}", url);

    let data = t
        .bytes()
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;

    let sub = parse_sub(&url, &data);

    let mut proxies = Vec::new();
    for line in sub.iter() {
        if let Line {
            url: Data::Url(urlx),
            err: None,
            ..
        } = line
        {
            // Normalization (uid/sig computation + validation) is now done
            // during parsing via the visitor pattern. Only collect valid results.
            proxies.push(urlx.clone());
        }
    }

    Ok(proxies)
}

#[cfg(test)]
mod tests {
    use rustc_hash::FxHashSet;
    use std::{
        fs::OpenOptions,
        io::{BufWriter, Write},
    };

    use tracing::Level;
    #[tokio::test]
    async fn test_download_sub() {
        tracing_subscriber::fmt()
            .compact()
            .with_max_level(Level::ERROR)
            .init();

        let subs = [
            "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
            // "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/reality",
            // "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vmess",
            // "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",
            // "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/shadowsocks",
            "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/vmess.txt",
            "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/vless.txt",
            "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/ss.txt",
            "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/trojan.txt",
            "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/mix.txt",
            // "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/V2RAY_SUB.txt",
            "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt",
            "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
            "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
            "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
            "https://raw.githubusercontent.com/shabane/kamaji/master/hub/b64/merged.txt",
            "https://raw.githubusercontent.com/MrPooyaX/VpnsFucking/main/Shenzo.txt",
            "https://raw.githubusercontent.com/MrPooyaX/SansorchiFucker/main/data.txt",
            // "https://mrpooyax.camdvr.org/api/ramezan/lena.php?sub=1",
            // "https://mrpooyax.camdvr.org/api/ramezan/run.php?sub=1",
            // "https://mrpooyax.camdvr.org/api/ramezan/v2raySH.php?sub=1",
            // "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/base64/mix",
            // "https://mrpooyax.camdvr.org/api/ramezan/alpha.php?sub=1",
            // "https://raw.githubusercontent.com/hkpc/V2ray-Configs/refs/heads/main/All_Configs_Sub.txt",
            // "https://raw.githubusercontent.com/v2clash/V2ray-Configs/refs/heads/main/All_Configs_Sub.txt",
            "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
            // "https://raw.githubusercontent.com/barry-far/V2ray-Configs/refs/heads/main/All_Configs_Sub.txt",
            // "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/main/config.txt",
            "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/refs/heads/main/All_Configs_Sub.txt",
            "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/refs/heads/master/sub/sub_merge.txt",
            "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
            "https://raw.githubusercontent.com/peasoft/NoMoreWalls/refs/heads/master/list_raw.txt",
            "https://raw.githubusercontent.com/SonzaiEkkusu/V2RayDumper/refs/heads/main/config.txt",
            "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/vless",
            "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/ss",
            "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/vmess",
            "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/trojan",
            "https://raw.githubusercontent.com/theGreatPeter/v2rayNodes/refs/heads/main/nodes.txt",
            // "https://raw.githubusercontent.com/NiREvil/vless/main/sub/G-Core",
            "https://raw.githubusercontent.com/NiREvil/vless/main/sub/SSTime",
            "https://raw.githubusercontent.com/coldwater-10/V2rayCollector/main/vmess_iran.txt",
            // "https://raw.githubusercontent.com/amirmohammad-mohammad-88/Sub-Reality-Azadi-config/Config/Azadi-Reality-Different",
            // "https://raw.githubusercontent.com/amirmohammad-mohammad-88/Sub-Reality-Azadi-config/Config/Config",
            // "https://raw.githubusercontent.com/amirmohammad-mohammad-88/Sub-Config-operator/Config/MCI.txt",
            // "https://raw.githubusercontent.com/amirmohammad-mohammad-88/Sub-Config-operator/Config/Mobinet.txt",
            // "https://raw.githubusercontent.com/amirmohammad-mohammad-88/Sub-Config-operator/Config/Mokhabrat.txt",
            // "https://raw.githubusercontent.com/amirmohammad-mohammad-88/Sub-Config-operator/Config/Rightel.txt",
            // "https://raw.githubusercontent.com/amirmohammad-mohammad-88/Sub-Config-operator/Config/irancell.txt",
            // "https://raw.githubusercontent.com/amirmohammad-mohammad-88/Sub-Config-operator/Config/shatel.txt",
            // "https://github.com/darknessm427/V2ray-Sub-Collector/blob/main/All_Darkness_Sub.txt",
            "https://github.com/Flikify/getNode/blob/main/v2ray.txt",
            // "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
            // "https://wUysQI.mcsslk.xyz/bdecc7a925302c827f5580fd6aa305c2",
            "https://raw.githubusercontent.com/Surfboardv2ray/Proxy-sorter/main/submerge/converted.txt",
            "https://raw.githubusercontent.com/thirtysixpw/v2ray-reaper/main/normal/mix",
            // "https://raw.githubusercontent.com/SamanGho/v2ray_collector/refs/heads/main/v2tel_links1.txt",
            // "https://raw.githubusercontent.com/SamanGho/v2ray_collector/refs/heads/main/v2tel_links2.txt",
            // "https://raw.githubusercontent.com/IranianCypherpunks/sub/main/config",
            // "https://raw.githubusercontent.com/sashalsk/V2Ray/main/V2Config",
            "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
            // "https://raw.githubusercontent.com/itsyebekhe/HiN-VPN/main/subscription/normal/mix",
            // "https://raw.githubusercontent.com/sarinaesmailzadeh/V2Hub/main/merged",
            // "https://raw.githubusercontent.com/freev2rayconfig/V2RAY_SUBSCRIPTION_LINK/main/v2rayconfigs.txt",
            "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",
            // "https://mrpooya.top/SuperApi/BE.php",
            // "https://servers.astms.com/api/sub?v=2.0.3&ref=bevpn.net",
            // "https://raw.githubusercontent.com/C4ssif3r/V2ray-sub/main/all.txt",
            "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",
            "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
            "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
            "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
            // "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
            "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",
            "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",
            "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
            "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",
            "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
            "https://raw.githubusercontent.com/expressalaki/ExpressVPN/refs/heads/main/configs3.txt",
            "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
            "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",
            "https://raw.githubusercontent.com/miladtahanian/Config-Collector/refs/heads/main/mixed_iran.txt",
            "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
            "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",
            "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
            "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",
            "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",
            "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
            "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
            "https://github.com/igareck/vpn-configs-for-russia/raw/refs/heads/main/BLACK_VLESS_RUS.txt",
            "https://github.com/Mr-Meshky/vify/raw/refs/heads/main/configs/vless.txt",
            "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
            "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
            "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
            "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
            "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
            // "https://wlrus.lol/confs/selected.txt",
        ];
        let mut hashes = Some(FxHashSet::default());

        let mut dest = BufWriter::new(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open("full.txt")
                .unwrap(),
        );

        for sub in subs {
            let url = url::Url::parse(sub).unwrap();

            if let Err(e) = crate::download_sub(url, &mut dest, &mut hashes).await {
                tracing::error!("{sub} | {e}");
            } else {
                tracing::info!("Downloaded {sub}");
            }
        }

        dest.flush().unwrap()
    }
}