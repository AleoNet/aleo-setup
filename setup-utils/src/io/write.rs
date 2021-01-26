//! Utilities for writing and reading group elements to buffers in parallel
use crate::{buffer_size, Result, UseCompression};

use snarkos_algorithms::cfg_chunks_mut;
use snarkos_models::curves::AffineCurve;

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::io::Write;

/// Used for writing elements to a buffer directly
pub trait Serializer {
    /// Writes a compressed or uncompressed element to the buffer
    fn write_element(&mut self, element: &impl AffineCurve, compression: UseCompression) -> Result<()>;

    /// Writes a list of elements serially
    fn write_elements_exact<G: AffineCurve>(&mut self, elements: &[G], compression: UseCompression) -> Result<()> {
        elements.iter().map(|el| self.write_element(el, compression)).collect()
    }
}

pub trait BatchSerializer {
    /// Initializes the buffer with the provided element
    fn init_element<G: AffineCurve>(&mut self, element: &G, compression: UseCompression) -> Result<()>;

    /// Writes multiple elements to the buffer. Internally calls `write_element`
    fn write_batch<G: AffineCurve>(&mut self, elements: &[G], compression: UseCompression) -> Result<()>;
}

impl<W: Write> Serializer for W {
    fn write_element(&mut self, element: &impl AffineCurve, compression: UseCompression) -> Result<()> {
        match compression {
            UseCompression::Yes => element.serialize(self)?,
            UseCompression::No => element.serialize_uncompressed(self)?,
        };
        Ok(())
    }
}

impl Serializer for [u8] {
    fn write_element(&mut self, element: &impl AffineCurve, compression: UseCompression) -> Result<()> {
        (&mut &mut *self).write_element(element, compression)
    }
}

impl BatchSerializer for [u8] {
    fn init_element<G: AffineCurve>(&mut self, element: &G, compression: UseCompression) -> Result<()> {
        let element_size = buffer_size::<G>(compression);
        cfg_chunks_mut!(self, element_size)
            .map(|buf| {
                (&mut buf[0..element_size]).write_element(element, compression)?;
                Ok(())
            })
            .collect::<Result<()>>()
    }

    /// Writes multiple elements to the buffer. Internally calls `write_element`
    fn write_batch<G: AffineCurve>(&mut self, elements: &[G], compression: UseCompression) -> Result<()> {
        let element_size = buffer_size::<G>(compression);
        cfg_chunks_mut!(self, element_size)
            .zip(elements)
            .map(|(buf, element)| {
                (&mut buf[0..element_size]).write_element(element, compression)?;
                Ok(())
            })
            .collect()
    }
}
