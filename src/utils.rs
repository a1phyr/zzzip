use std::io;

pub trait ReadLE: io::Read {
    #[inline]
    fn read_u8(&mut self) -> io::Result<u8> {
        let mut byte = [0];
        self.read_exact(&mut byte)?;
        Ok(byte[0])
    }

    #[inline]
    fn read_u16(&mut self) -> io::Result<u16> {
        let mut bytes = [0; 2];
        self.read_exact(&mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    #[inline]
    fn read_u32(&mut self) -> io::Result<u32> {
        let mut bytes = [0; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    #[inline]
    fn read_u64(&mut self) -> io::Result<u64> {
        let mut bytes = [0; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    #[inline]
    fn read_u128(&mut self) -> io::Result<u128> {
        let mut bytes = [0; 16];
        self.read_exact(&mut bytes)?;
        Ok(u128::from_le_bytes(bytes))
    }
}

impl<R: io::Read + ?Sized> ReadLE for R {}

pub trait WriteLE: io::Write {
    #[inline]
    fn write_u8(&mut self, byte: u8) -> io::Result<()> {
        self.write_all(&[byte])
    }

    #[inline]
    fn write_u16(&mut self, bytes: u16) -> io::Result<()> {
        let buf = bytes.to_le_bytes();
        self.write_all(&buf)
    }

    #[inline]
    fn write_u32(&mut self, bytes: u32) -> io::Result<()> {
        let buf = bytes.to_le_bytes();
        self.write_all(&buf)
    }

    #[inline]
    fn write_u64(&mut self, bytes: u64) -> io::Result<()> {
        let buf = bytes.to_le_bytes();
        self.write_all(&buf)
    }

    #[inline]
    fn write_u128(&mut self, bytes: u128) -> io::Result<()> {
        let buf = bytes.to_le_bytes();
        self.write_all(&buf)
    }
}

impl<W: io::Write + ?Sized> WriteLE for W {}
