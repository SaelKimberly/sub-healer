use base64::{Engine as _, engine::general_purpose};
use bytes::{BufMut, BytesMut};
use futures::stream::Stream;
use memchr::{memchr, memchr2};
use pin_project::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

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
    /// Определенный тип кодирования (определяется автоматически)
    encoding: Option<Encoding>,
    /// Флаг достижения конца потока
    eof: bool,
}

impl<R: AsyncRead> Base64LineStream<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: Box::pin(reader),
            read_buf: BytesMut::with_capacity(4096), // Буфер чтения 4KB
            decoded_buf: BytesMut::with_capacity(4096), // Буфер декодирования
            encoding: None,
            eof: false,
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

        // Если спец. символы еще не встретились, оставаемся в Unknown (None).
        // Алфавит [A-Za-z0-9] одинаков для обоих, поэтому можем декодировать как Standard
        // по умолчанию, пока не встретим различающийся символ.
    }

    /// Декодирует данные из `read_buf` в `decoded_buf`
    fn process_decode(&mut self) -> Result<(), base64::DecodeError> {
        // Base64 кодируется блоками по 4 символа -> 3 байта.
        // Мы можем декодировать только полные блоки.
        // Чтобы не ломать поток, декодируем количество байт кратное 4.
        let total_len = self.read_buf.len();
        // Накопили мало данных и не достигли конца потока — ждем еще
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

        // Определяем движок. Если еще неdetected, пробуем угадать или используем Standard
        self.detect_encoding();

        let engine = match self.encoding {
            Some(Encoding::UrlSafe) => &general_purpose::URL_SAFE,
            _ => &general_purpose::STANDARD, // Default или Explicit Standard
        };

        // Декодируем. Используем Vec так как нужен изменяемый буфер точного размера.
        let decoded_bytes = engine.decode(to_decode.as_ref())?;
        self.decoded_buf.extend_from_slice(&decoded_bytes);

        Ok(())
    }
}

impl<R: AsyncRead + Unpin> Stream for Base64LineStream<R> {
    type Item = std::io::Result<String>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

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
        } else {
            println!("No newline found")
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
        } else {
            println!("Not EOF")
        }

        // 3. Читаем новые данные из потока
        // Используем read_buf для чтения напрямую в наш буфер
        let mut read_buf = this.read_buf.split_off(this.read_buf.len());
        read_buf.reserve(1024); // Размер временного буфера для чтения

        let mut buffer = ReadBuf::new(&mut read_buf);

        let poll = this.reader.as_mut().poll_read(cx, &mut buffer);
        match poll {
            Poll::Ready(Err(e)) => {
                // Возвращаем временный буфер обратно, чтобы не потерять память
                this.read_buf.unsplit(read_buf);
                return Poll::Ready(Some(Err(e)));
            }
            Poll::Pending => {
                // Возвращаем временный буфер обратно, чтобы не потерять память
                this.read_buf.unsplit(read_buf);
                return Poll::Pending;
            }
            _ => {}
        };
        let filled = buffer.filled().len();
        if filled == 0 {
            this.eof = true;
        } else {
            read_buf.truncate(filled);
            this.read_buf.unsplit(read_buf);
        }

        println!("Read {} bytes", filled);

        // Декодируем накопленное
        if let Err(e) = this.process_decode() {
            return Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e,
            ))));
        }

        // Пытаемся вернуть строку снова
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use futures::{StreamExt, TryStreamExt};
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    use crate::utils::b64stream::Base64LineStream;

    #[tokio::test]
    async fn test_b64_stream() {
        let client = reqwest::Client::new();
        let t = client.get(
            "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Base64/WHITE-SNI-RU-all-base64.txt"
        ).send().await.unwrap().error_for_status().unwrap();

        let stream = t
            .bytes_stream()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
            .into_async_read()
            .compat();

        let mut b64_stream = Base64LineStream::new(stream);

        while let Some(line) = b64_stream.next().await {
            println!("- {}", line.unwrap());
        }
    }
}
