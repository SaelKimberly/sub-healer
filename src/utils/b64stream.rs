use base64::{Engine as _, engine::general_purpose};
use bytes::{BufMut, BytesMut};
use futures::TryStreamExt;
use futures::stream::Stream;
use memchr::{memchr, memchr2};
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio_util::compat::FuturesAsyncReadCompatExt;

/// Режим работы потока (auto-detected)
#[derive(Debug, Clone, Copy, PartialEq)]
enum StreamMode {
    /// Режим еще не определен
    Unknown,
    /// Base64 кодированный поток
    Base64,
    /// Plain UTF-8 поток
    PlainUtf8,
}

/// Возможные варианты кодирования Base64
#[derive(Debug, Clone, Copy, PartialEq)]
enum Encoding {
    /// Стандартная кодировка (A-Za-z0-9+/)
    Standard,
    /// URL-safe кодировка (A-Za-z0-9-_)
    UrlSafe,
}

/// Обертка над потоком, декодирующая Base64 и разбивающая его на строки
#[pin_project]
pub struct Base64LineStream<R> {
    /// Входной поток чтения
    #[pin]
    reader: Pin<Box<R>>,
    /// Буфер для сырых данных из Base64
    read_buf: BytesMut,
    /// Буфер для декодированных данных (байты)
    decoded_buf: BytesMut,
    /// Режим работы потока (определяется автоматически)
    mode: StreamMode,
    /// Определенный тип кодирования (определяется автоматически)
    encoding: Option<Encoding>,
    /// Флаг достижения конца потока
    eof: bool,
    /// fragment encoding
    frag_enc: Option<&'static encoding_rs::Encoding>,
}

impl<R: AsyncRead> Base64LineStream<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: Box::pin(reader),
            read_buf: BytesMut::with_capacity(4096),
            decoded_buf: BytesMut::with_capacity(4096),
            mode: StreamMode::Unknown,
            encoding: None,
            eof: false,
            frag_enc: None,
        }
    }

    /// Определяет тип кодирования (Standard или UrlSafe) на основе наличия спец. символов
    fn detect_encoding(&mut self) {
        if self.encoding.is_some() {
            return;
        }

        // Ищем + или /
        if memchr2(b'+', b'/', &self.read_buf).is_some() {
            self.encoding = Some(Encoding::Standard);
        } else
        // Ищем - или _
        if memchr2(b'-', b'_', &self.read_buf).is_some() {
            self.encoding = Some(Encoding::UrlSafe);
        }

        // Если спец. символы еще не встретились, используем Standard по умолчанию
    }

    /// Декодирует данные из `read_buf` в `decoded_buf`
    fn process_decode(&mut self) -> Result<(), base64::DecodeError> {
        let total_len = self.read_buf.len();

        // Need at least some data to process
        if total_len == 0 {
            return Ok(());
        }

        // Auto-detect mode on first call
        if self.mode == StreamMode::Unknown {
            // Need at least 4 bytes to test base64
            if total_len < 4 && !self.eof {
                return Ok(());
            }

            // Try base64 mode first - check if we can decode
            let split_len = total_len - (total_len % 4);
            if split_len >= 4 {
                // Copy data for testing (needed because we need to try decode without consuming)
                // Detect encoding first (using original borrow)
                self.detect_encoding();
                let test_data = &self.read_buf[..split_len];

                let engine = match self.encoding {
                    Some(Encoding::UrlSafe) => &general_purpose::URL_SAFE,
                    _ => &general_purpose::STANDARD,
                };

                if let Ok(decoded) = engine.decode(test_data) {
                    // Base64 decode succeeded - check UTF-8 validity
                    if std::str::from_utf8(&decoded).is_ok() {
                        self.mode = StreamMode::Base64;
                        // Now actually consume the data
                        let to_decode = self.read_buf.split_to(split_len);
                        let _ = engine.decode(to_decode.as_ref()).unwrap();
                        self.decoded_buf.extend_from_slice(&decoded);
                        return Ok(());
                    }
                }
            }

            // Try plain UTF-8 mode
            if std::str::from_utf8(&self.read_buf).is_ok() {
                self.mode = StreamMode::PlainUtf8;
                self.decoded_buf.extend_from_slice(&self.read_buf);
                self.read_buf.clear();
                return Ok(());
            }

            // Neither base64 nor UTF-8 worked → error
            return Err(base64::DecodeError::InvalidByte(0, 0));
        }

        // Mode already detected - use appropriate decode method
        match self.mode {
            StreamMode::Base64 => {
                let total_len = self.read_buf.len();

                if total_len < 4 && !self.eof {
                    return Ok(());
                }

                if self.eof && !total_len.is_multiple_of(4) {
                    self.read_buf.put_bytes(b'=', 4 - total_len % 4);
                }

                let split_len = total_len - (total_len % 4);
                if split_len == 0 {
                    return Ok(());
                }

                let to_decode = self.read_buf.split_to(split_len);
                self.detect_encoding();

                let engine = match self.encoding {
                    Some(Encoding::UrlSafe) => &general_purpose::URL_SAFE,
                    _ => &general_purpose::STANDARD,
                };

                let decoded_bytes = engine.decode(to_decode.as_ref())?;
                self.decoded_buf.extend_from_slice(&decoded_bytes);
            }
            StreamMode::PlainUtf8 => {
                if !self.read_buf.is_empty() {
                    if std::str::from_utf8(&self.read_buf).is_ok() {
                        self.decoded_buf.extend_from_slice(&self.read_buf);
                        self.read_buf.clear();
                    } else {
                        return Err(base64::DecodeError::InvalidByte(0, 0));
                    }
                }
            }
            StreamMode::Unknown => {}
        }

        Ok(())
    }
}

impl<R: AsyncRead + Unpin> Stream for Base64LineStream<R> {
    type Item = std::io::Result<String>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            // 1. Пытаемся извлечь строку из уже декодированного буфера
            if let Some(newline_pos) = memchr(b'\n', &this.decoded_buf) {
                // Извлекаем байты до \n
                let line_bytes = this.decoded_buf.split_to(newline_pos + 1);
                // Удаляем сам символ \n
                let mut line_bytes = line_bytes.freeze();
                line_bytes.truncate(line_bytes.len() - 1);

                // Обработка \r\n (удаляем \r в конце, если есть)
                if line_bytes.last() == Some(&b'\r') {
                    line_bytes.truncate(line_bytes.len() - 1);
                }

                // Конвертируем в String
                return Poll::Ready(Some(
                    str::from_utf8(&line_bytes)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                        .map(ToOwned::to_owned),
                ));
            }

            // 2. Если строк не найдено, проверяем, не достигнут ли конец потока и пусты ли буферы
            if this.eof {
                if this.decoded_buf.is_empty() {
                    return Poll::Ready(None);
                } else {
                    // Возвращаем остаток буфера как последнюю строку
                    let remainder = this.decoded_buf.split();
                    return Poll::Ready(Some(
                        str::from_utf8(&remainder)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                            .map(ToOwned::to_owned),
                    ));
                }
            }

            // 3. Читаем новые данные из потока
            let mut temp_buf = Box::new_uninit_slice(1024);
            let mut buffer = ReadBuf::uninit(&mut temp_buf);

            let poll = this.reader.as_mut().poll_read(cx, &mut buffer);

            match poll {
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
                _ => {}
            };

            match buffer.filled() {
                &[] => {
                    this.eof = true;
                }
                filled => {
                    this.read_buf.extend_from_slice(filled);
                }
            }

            // Декодируем накопленное
            if let Err(e) = this.process_decode() {
                return Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e,
                ))));
            }

            // Loop back to check decoded_buf for lines after new data decoded
        }
    }
}

pub async fn subscription_line_stream(
    url: url::Url,
) -> reqwest::Result<impl Stream<Item = std::io::Result<String>>> {
    let client = reqwest::Client::builder()
        .user_agent("Xray-Rs/0.1.0")
        .build()?;

    let t = if matches!(
        url.host_str(),
        Some("raw.githubusercontent.com" | "github.com")
    ) && let Ok(auth) = std::env::var("GITHUB_TOKEN")
    {
        client.get(url.as_str()).bearer_auth(auth)
    } else {
        client.get(url.as_str())
    };
    let t = t.send().await?.error_for_status()?;

    let stream = t
        .bytes_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
        .into_async_read()
        .compat();

    Ok(Base64LineStream::new(stream))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use futures::StreamExt;
    use smartstring::LazyCompact;

    use crate::utils::percent_encoding::PercentDecode;

    use super::subscription_line_stream;

    #[tokio::test]
    async fn test_b64_stream() {
        let mut b64_stream = subscription_line_stream(
            url::Url::parse("https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Base64/WHITE-SNI-RU-all-base64.txt")
            .unwrap()
        ).await.unwrap();

        let mut count = 0;
        while let Some(line) = b64_stream.next().await.transpose().unwrap() {
            eprintln!("- {line:?}");
            count += 1;
        }
        assert!(count > 0, "Should have read some lines");
    }

    #[tokio::test]
    async fn test_utf_stream() {
        let mut total = 0;

        let sources = [
            "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",
            "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
            "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
            "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
            "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
            "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",
            "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",
            "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
            "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",
            "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
            "https://raw.githubusercontent.com/expressalaki/ExpressVPN/main/configs3.txt",
            "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
            "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",
            "https://github.com/miladtahanian/Config-Collector/raw/refs/heads/main/vless_iran.txt",
            "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
            "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",
            "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
            "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",
            "https://github.com/Argh94/Proxy-List/raw/refs/heads/main/All_Config.txt",
            "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
            "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
            "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
            "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
            "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
            "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
            "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
            "https://raw.githubusercontent.com/gbwltg/gbwl/refs/heads/main/m3EsPqwmlc",
            "https://storage.yandexcloud.net/cid-vpn/whitelist.txt",
        ];

        let mut urls = vec![];

        for s in sources {
            let mut count = 0;
            let Ok(mut utf_stream) = subscription_line_stream(url::Url::parse(s).unwrap()).await
            else {
                eprintln!("Skipping {s}");
                continue;
            };

            while let Some(line) = utf_stream.next().await.transpose().unwrap() {
                if let Some((
                    schema @ ("vless" | "vmess" | "hhysteria2" | "hhysteria" | "hysteria2"
                    | "hysteria" | "hhy2" | "hhy" | "hy2" | "hy" | "ss" | "ssr"
                    | "trojan" | "tuic" | "warp" | "anytls"),
                    _url,
                )) = line.split_once("://")
                {
                    let schema = smartstring::SmartString::<LazyCompact>::from(schema);
                    urls.push((schema, line.trim_end().to_owned()));
                } else if let Some((_, s)) = urls.last_mut() {
                    s.push('\n');
                    s.push_str(line.as_str());
                    continue;
                }

                count += 1;
            }

            eprintln!("{s}: {count}");
            total += count;
        }

        assert!(total > 0, "Should have read some lines");
    }
}
