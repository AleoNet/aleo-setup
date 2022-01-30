use crate::{buffer_size, CheckForCorrectness, Error, Result, UseCompression};

use snarkvm_algorithms::cfg_chunks;
use snarkvm_curves::AffineCurve;

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use snarkvm_utilities::CanonicalDeserialize;
use std::io::Read;

/// Used for reading 1 group element from a serialized buffer
pub trait Deserializer {
    /// Reads 1 compressed or uncompressed element
    fn read_element<G: AffineCurve>(
        &mut self,
        compression: UseCompression,
        check_correctness: CheckForCorrectness,
    ) -> Result<G>;

    /// Reads exact number of elements
    fn read_elements_exact<G: AffineCurve>(
        &mut self,
        num: usize,
        compression: UseCompression,
        check_correctness: CheckForCorrectness,
    ) -> Result<Vec<G>> {
        (0..num)
            .map(|_| self.read_element(compression, check_correctness))
            .collect()
    }

    /// Reads 1 compressed or uncompressed element to a pre-allocated element
    fn read_element_preallocated<G: AffineCurve>(
        &mut self,
        el: &mut G,
        compression: UseCompression,
        check_correctness: CheckForCorrectness,
    ) -> Result<()>;
}

pub trait BatchDeserializer {
    /// Reads multiple elements from the buffer
    fn read_batch<G: AffineCurve>(
        &self,
        compression: UseCompression,
        check_correctness: CheckForCorrectness,
    ) -> Result<Vec<G>>;

    /// Reads multiple elements from the buffer to a preallocated array of Group elements
    fn read_batch_preallocated<G: AffineCurve>(
        &self,
        elements: &mut [G],
        compression: UseCompression,
        check_correctness: CheckForCorrectness,
    ) -> Result<()>;
}

impl<R: Read> Deserializer for R {
    fn read_element<G: AffineCurve>(
        &mut self,
        compression: UseCompression,
        check_for_correctness: CheckForCorrectness,
    ) -> Result<G> {
        let point: G = match compression {
            UseCompression::Yes => CanonicalDeserialize::deserialize(self)?,
            UseCompression::No => CanonicalDeserialize::deserialize_uncompressed(self)?,
        };

        if (check_for_correctness == CheckForCorrectness::Full
            || check_for_correctness == CheckForCorrectness::OnlyNonZero)
            && point.is_zero()
        {
            return Err(Error::PointAtInfinity);
        }

        Ok(point)
    }

    fn read_element_preallocated<G: AffineCurve>(
        &mut self,
        el: &mut G,
        compression: UseCompression,
        check_correctness: CheckForCorrectness,
    ) -> Result<()> {
        *el = self.read_element(compression, check_correctness)?;
        Ok(())
    }
}

// We implement this for slices so that the consumer does not need to write the `&mut slice.as_ref()`
// boilerplate in each call. This should have no performance overhead
impl Deserializer for [u8] {
    fn read_element<G: AffineCurve>(
        &mut self,
        compression: UseCompression,
        check_correctness: CheckForCorrectness,
    ) -> Result<G> {
        (&*self).read_element(compression, check_correctness)
    }

    fn read_element_preallocated<G: AffineCurve>(
        &mut self,
        el: &mut G,
        compression: UseCompression,
        check_correctness: CheckForCorrectness,
    ) -> Result<()> {
        *el = self.read_element(compression, check_correctness)?;
        Ok(())
    }
}

// We implement this specifically for slices so that we can take advantage
// of parallel iterators
impl BatchDeserializer for [u8] {
    fn read_batch<G: AffineCurve>(
        &self,
        compression: UseCompression,
        check_correctness: CheckForCorrectness,
    ) -> Result<Vec<G>> {
        let size = buffer_size::<G>(compression);
        cfg_chunks!(&*self, size)
            .map(|mut buf| buf.read_element(compression, check_correctness))
            .collect::<Result<Vec<_>>>()
    }

    fn read_batch_preallocated<G: AffineCurve>(
        &self,
        elements: &mut [G],
        compression: UseCompression,
        check_correctness: CheckForCorrectness,
    ) -> Result<()> {
        let size = buffer_size::<G>(compression);
        cfg_chunks!(&*self, size)
            .zip(elements)
            .map(|(mut buf, el)| buf.read_element_preallocated(el, compression, check_correctness))
            .collect::<Result<Vec<_>>>()?;
        Ok(())
    }
}
