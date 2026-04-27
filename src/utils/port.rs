use std::ops::Range;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum PortDecl {
    Single(u16),
    Range(Range<u16>),
}

impl std::fmt::Display for PortDecl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortDecl::Single(p) => write!(f, "{}", p),
            PortDecl::Range(r) => write!(f, "{}-{}", r.start, r.end),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PortSpec {
    ports: Vec<PortDecl>,
    total: usize,
}

impl std::fmt::Display for PortSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, p) in self.ports.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?
            }
            match p {
                PortDecl::Single(p) => f.write_str(p.to_string().as_ref())?,
                PortDecl::Range(Range { start, end }) => {
                    f.write_str(start.to_string().as_ref())?;
                    f.write_str("-")?;
                    f.write_str(end.to_string().as_ref())?
                }
            }
        }
        Ok(())
    }
}

impl PortSpec {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            ports: Vec::new(),
            total: 0,
        }
    }
    pub fn new_with(port: u16) -> Self {
        Self {
            ports: vec![PortDecl::Single(port)],
            total: 1,
        }
    }

    pub fn add(&mut self, port: u16) -> bool {
        for decl in self.ports.iter() {
            match decl {
                &PortDecl::Single(p) if p == port => return false,
                PortDecl::Range(r) if r.contains(&port) => return false,
                _ => {}
            }
        }

        self.ports.push(PortDecl::Single(port));
        self.total += 1;
        true
    }
    pub fn add_range(&mut self, range: Range<u16>) {
        let mut merged = false;
        self.ports.retain_mut(|decl| match decl {
            // If single-port entry persist in range, remove
            &mut PortDecl::Single(p) if range.contains(&p) => false,
            // If range is fully or partially contained in existing range, merge them into one
            PortDecl::Range(r) if range.contains(&r.start) || range.contains(&r.end) => {
                let old_len = r.len();
                merged = true;
                r.start = range.start.min(r.start);
                r.end = range.end.max(r.end);
                let new_len = r.len();
                self.total += new_len - old_len;
                true
            }
            _ => true,
        });
        if !merged {
            self.total += range.len();
            self.ports.push(PortDecl::Range(range));
        }
    }

    pub const fn contains(&self, port: u16) -> bool {
        let arr = self.ports.as_slice();
        let mut idx = 0;
        loop {
            match &arr[idx] {
                PortDecl::Single(p) if *p == port => return true,
                PortDecl::Range(r) if r.start <= port && port < r.end => return true,
                _ => {}
            }
            if idx == self.ports.len() {
                break false;
            }
            idx += 1;
        }
    }

    pub const fn length(&self) -> usize {
        let mut length = 0_usize;
        let mut idx = 0;
        let arr = self.ports.as_slice();
        loop {
            match &arr[idx] {
                PortDecl::Single(_) => {
                    length += 1;
                    idx += 1;
                }
                PortDecl::Range(r) => {
                    length += (r.end - r.start + 1) as usize;
                    idx += 1;
                }
            }
            if idx == self.ports.len() {
                break length;
            }
        }
    }

    /// Get the first port
    pub const fn first(&self) -> Option<u16> {
        match *self.ports.as_slice() {
            [PortDecl::Single(p), ..] => Some(p),
            [PortDecl::Range(Range { start, .. }), ..] => Some(start),
            _ => None,
        }
    }

    /// Get the last port
    pub const fn last(&self) -> Option<u16> {
        match *self.ports.as_slice() {
            [.., PortDecl::Single(p)] => Some(p),
            [.., PortDecl::Range(Range { end, .. })] => Some(end),
            _ => None,
        }
    }

    pub fn sort(mut self) -> Self {
        self.ports.sort_by_key(|p| match p {
            PortDecl::Single(p) => *p,
            PortDecl::Range(r) => r.start,
        });
        self
    }

    pub fn iter(&self) -> impl Iterator<Item = u16> {
        PortSpecIter {
            spec: self,
            outer_idx: 0,
            inner_idx: 0,
        }
    }

    pub fn iter_raw(&self) -> impl Iterator<Item = &PortDecl> {
        self.ports.iter()
    }
}

struct PortSpecIter<'a> {
    spec: &'a PortSpec,
    outer_idx: usize,
    inner_idx: u16,
}

impl Iterator for PortSpecIter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        match self.spec.ports.get(self.outer_idx)? {
            PortDecl::Single(port) => {
                self.outer_idx += 1;
                Some(*port)
            }
            PortDecl::Range(r) => {
                let port = r.start + self.inner_idx;
                if r.contains(&port) {
                    self.inner_idx += 1;
                    Some(port)
                } else {
                    self.outer_idx += 1;
                    self.inner_idx = 0;
                    self.next()
                }
            }
        }
    }
}
