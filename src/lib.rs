use std::marker::PhantomData;

use cipher::{
    Array, BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, ParBlocksSizeUser,
    StreamCipherBackend, StreamCipherCore, StreamCipherCoreWrapper,
    array::ArraySize,
    consts::{U1, U4, U8, U32, U64, U128},
};
use utils::{a_mul, ainv_mul, t};
use zeroize::ZeroizeOnDrop;

mod utils;

pub type Dstu8845_256 = StreamCipherCoreWrapper<Dstu8845Core<U32, U4>>;
pub type Dstu8845_512 = StreamCipherCoreWrapper<Dstu8845Core<U64, U8>>;

macro_rules! gamma_init_step {
    ($n:expr, $tmp:ident, $self:ident) => {
        $self.s[$n] = a_mul($self.s[$n])
            ^ $self.s[($n + 13) % 16]
            ^ ainv_mul($self.s[($n + 11) % 16])
            ^ ($self.r[0].overflowing_add($self.s[($n + 15) % 16]).0)
            ^ $self.r[1];
        $tmp = $self.r[1].overflowing_add($self.s[($n + 13) % 16]).0;
        $self.r[1] = t($self.r[0]);
        $self.r[0] = $tmp;
    };
}

macro_rules! gamma_next_step {
    ($n:expr, $tmp:ident, $self:ident) => {
        $self.s[$n] =
            a_mul($self.s[$n]) ^ $self.s[($n + 13) % 16] ^ ainv_mul($self.s[($n + 11) % 16]);
        $tmp = $self.r[1].overflowing_add($self.s[($n + 13) % 16]).0;
        $self.r[1] = t($self.r[0]);
        $self.r[0] = $tmp;
        $self.gamma[$n] =
            ($self.r[0].overflowing_add($self.s[$n]).0) ^ $self.r[1] ^ $self.s[($n + 1) % 16];
    };
}

pub struct Dstu8845Core<L: ArraySize, N: ArraySize> {
    key: Array<u64, N>,
    s: [u64; 16],
    r: [u64; 2],
    gamma: [u64; 16],
    gamma_cntr: usize,
    _marker: PhantomData<L>,
}

#[cfg(feature = "zeroize")]
impl<L, N> ZeroizeOnDrop for Dstu8845Core<L, N>
where
    L: ArraySize,
    N: ArraySize,
{
}

impl<L, N> KeySizeUser for Dstu8845Core<L, N>
where
    L: ArraySize,
    N: ArraySize,
{
    type KeySize = L;
}

impl<L, N> IvSizeUser for Dstu8845Core<L, N>
where
    L: ArraySize,
    N: ArraySize,
{
    type IvSize = U32;
}

impl<L, N> BlockSizeUser for Dstu8845Core<L, N>
where
    L: ArraySize,
    N: ArraySize,
{
    type BlockSize = U128;
}

impl<L, N> ParBlocksSizeUser for Dstu8845Core<L, N>
where
    L: ArraySize,
    N: ArraySize,
{
    type ParBlocksSize = U1;
}

impl KeyIvInit for Dstu8845Core<U32, U4> {
    fn new(key: &cipher::Key<Self>, iv: &cipher::Iv<Self>) -> Self {
        Dstu8845Core::<U32, U4>::new(*key, *iv)
    }
}

impl KeyIvInit for Dstu8845Core<U64, U8> {
    fn new(key: &cipher::Key<Self>, iv: &cipher::Iv<Self>) -> Self {
        Dstu8845Core::<U64, U8>::new(*key, *iv)
    }
}

impl<L, N> StreamCipherBackend for Dstu8845Core<L, N>
where
    L: ArraySize,
    N: ArraySize,
{
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut cipher::Block<Self>) {
        block.copy_from_slice(&self.next_block());
    }
}

impl<L, N> StreamCipherCore for Dstu8845Core<L, N>
where
    L: ArraySize,
    N: ArraySize,
{
    #[inline(always)]
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }

    fn process_with_backend(
        &mut self,
        f: impl cipher::StreamCipherClosure<BlockSize = Self::BlockSize>,
    ) {
        f.call(self);
    }
}

impl Dstu8845Core<U32, U4> {
    pub fn new(key: Array<u8, U32>, iv: Array<u8, U32>) -> Self {
        let key = unsafe { std::mem::transmute::<Array<u8, U32>, Array<u64, U4>>(key) };

        let iv = unsafe { std::mem::transmute::<Array<u8, U32>, Array<u64, U4>>(iv) };

        let mut this = Self {
            key,
            s: [0; 16],
            r: [0; 2],
            gamma: [0; 16],
            gamma_cntr: 0,
            _marker: PhantomData,
        };

        this.set_iv(iv);

        this
    }

    fn set_iv(&mut self, iv: Array<u64, U4>) {
        self.s[0] = self.key[3] ^ iv[0];
        self.s[1] = self.key[2];
        self.s[2] = self.key[1] ^ iv[1];
        self.s[3] = self.key[0] ^ iv[2];
        self.s[4] = self.key[3];
        self.s[5] = self.key[2] ^ iv[3];
        self.s[6] = !self.key[1];
        self.s[7] = !self.key[0];
        self.s[8] = self.key[3];
        self.s[9] = self.key[2];
        self.s[10] = !self.key[1];
        self.s[11] = self.key[0];
        self.s[12] = self.key[3];
        self.s[13] = !self.key[2];
        self.s[14] = self.key[1];
        self.s[15] = !self.key[0];

        self.r = [0; 2];

        self.init_gamma();
    }
}

impl Dstu8845Core<U64, U8> {
    pub fn new(key: Array<u8, U64>, iv: Array<u8, U32>) -> Self {
        let key = unsafe { std::mem::transmute::<Array<u8, U64>, Array<u64, U8>>(key) };

        let iv = unsafe { std::mem::transmute::<Array<u8, U32>, Array<u64, U4>>(iv) };

        let mut this = Self {
            key,
            s: [0; 16],
            r: [0; 2],
            gamma: [0; 16],
            gamma_cntr: 0,
            _marker: PhantomData,
        };

        this.set_iv(iv);

        this
    }

    fn set_iv(&mut self, iv: Array<u64, U4>) {
        self.s[0] = self.key[7] ^ iv[0];
        self.s[1] = self.key[6];
        self.s[2] = self.key[5];
        self.s[3] = self.key[4] ^ iv[1];
        self.s[4] = self.key[3];
        self.s[5] = self.key[2] ^ iv[2];
        self.s[6] = self.key[1];
        self.s[7] = !self.key[0];
        self.s[8] = self.key[4] ^ iv[3];
        self.s[9] = !self.key[6];
        self.s[10] = self.key[5];
        self.s[11] = !self.key[7];
        self.s[12] = self.key[3];
        self.s[13] = self.key[2];
        self.s[14] = !self.key[1];
        self.s[15] = self.key[0];

        self.r = [0; 2];

        self.init_gamma();
    }
}

impl<L, N> Dstu8845Core<L, N>
where
    L: ArraySize,
    N: ArraySize,
{
    pub fn next_block(&mut self) -> [u8; 128] {
        let mut block = [0; 128];

        for j in 0..self.gamma.len() {
            let chunk = self.gamma[self.gamma_cntr].to_le_bytes();

            for i in 0..8 {
                block[j * 8 + i] = chunk[i];
            }

            self.gamma_cntr += 1;

            if self.gamma_cntr == 16 {
                self.gamma_next();
            }
        }

        block
    }

    fn gamma_next(&mut self) {
        let mut tmp;

        gamma_next_step!(0, tmp, self);
        gamma_next_step!(1, tmp, self);
        gamma_next_step!(2, tmp, self);
        gamma_next_step!(3, tmp, self);
        gamma_next_step!(4, tmp, self);
        gamma_next_step!(5, tmp, self);
        gamma_next_step!(6, tmp, self);
        gamma_next_step!(7, tmp, self);
        gamma_next_step!(8, tmp, self);
        gamma_next_step!(9, tmp, self);
        gamma_next_step!(10, tmp, self);
        gamma_next_step!(11, tmp, self);
        gamma_next_step!(12, tmp, self);
        gamma_next_step!(13, tmp, self);
        gamma_next_step!(14, tmp, self);
        gamma_next_step!(15, tmp, self);

        self.gamma_cntr = 0;
    }

    fn init_gamma(&mut self) {
        #[cfg(target_endian = "big")]
        panic!("big endian is not supported");

        let mut tmp;

        for _ in 0..2 {
            gamma_init_step!(0, tmp, self);
            gamma_init_step!(1, tmp, self);
            gamma_init_step!(2, tmp, self);
            gamma_init_step!(3, tmp, self);
            gamma_init_step!(4, tmp, self);
            gamma_init_step!(5, tmp, self);
            gamma_init_step!(6, tmp, self);
            gamma_init_step!(7, tmp, self);
            gamma_init_step!(8, tmp, self);
            gamma_init_step!(9, tmp, self);
            gamma_init_step!(10, tmp, self);
            gamma_init_step!(11, tmp, self);
            gamma_init_step!(12, tmp, self);
            gamma_init_step!(13, tmp, self);
            gamma_init_step!(14, tmp, self);
            gamma_init_step!(15, tmp, self);
        }

        self.gamma_next();
    }
}

#[cfg(test)]
mod test {
    use cipher::{KeyIvInit, StreamCipher};

    use super::*;

    #[test]
    fn test_dstu8845_256() {
        #[rustfmt::skip]
        let iv_1: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        #[rustfmt::skip]
        let iv_2: [u8; 32] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        #[rustfmt::skip]
        let k256_1: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        ];

        #[rustfmt::skip]
        let k256_2: [u8; 32] = [
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        ];

        #[rustfmt::skip]
        let k256_1_iv_1: [u64; 8] = [
            0xe442d15345dc66cau64, 0xf47d700ecc66408a, 0xb4cb284b5477e641, 0xa2afc9092e4124b0,
            0x728e5fa26b11a7d9, 0xe6a7b9288c68f972, 0x70eb3606de8ba44c, 0xaced7956bd3e3de7,
        ];

        #[rustfmt::skip]
        let k256_2_iv_1: [u64; 8] = [
            0xa7510b38c7a95d1d, 0xcd5ea28a15b8654f, 0xc5e2e2771d0373b2, 0x98ae829686d5fcee,
        0x45bddf65c523dbb8, 0x32a93fcdd950001f, 0x752a7fb588af8c51, 0x9de92736664212d4,
        ];

        #[rustfmt::skip]
        let k256_1_iv_2: [u64; 8] = [
            0xfe44a2508b5a2acd, 0xaf355b4ed21d2742, 0xdcd7fdd6a57a9e71, 0x5d267bd2739fb5eb,
            0xb22eee96b2832072, 0xc7de6a4cdaa9a847, 0x72d5da93812680f2, 0x4a0acb7e93da2ce0,
        ];

        #[rustfmt::skip]
        let k256_2_iv_2: [u64; 8] = [
            0xe6d0efd9cea5abcd, 0x1e78ba1a9b0e401e, 0xbcfbea2c02ba0781, 0x1bd375588ae08794,
            0x5493cf21e114c209, 0x66cd5d7cc7d0e69a, 0xa5cdb9f3380d07fa, 0x2940d61a4d4e9ce4,
        ];

        let cases = [
            (iv_1, k256_1, k256_1_iv_1),
            (iv_1, k256_2, k256_2_iv_1),
            (iv_2, k256_1, k256_1_iv_2),
            (iv_2, k256_2, k256_2_iv_2),
        ];

        for (iv, k, r) in cases {
            let mut z = [0; 64];

            let mut encoder = Dstu8845_256::new_from_slices(&k, &iv).unwrap();
            encoder.apply_keystream(&mut z);

            unsafe {
                assert_eq!(std::mem::transmute::<_, [u64; 8]>(z), r);
            }
        }
    }

    #[test]
    fn test_dstu8845_512() {
        #[rustfmt::skip]
        let iv_1: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        #[rustfmt::skip]
        let iv_2: [u8; 32] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        #[rustfmt::skip]
        let k512_1: [u8; 64] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        ];

        #[rustfmt::skip]
        let k512_2: [u8; 64] = [
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        ];

        #[rustfmt::skip]
        let k512_1_iv_1: [u64; 8] = [
            0xf5b9ab51100f8317, 0x898ef2086a4af395, 0x59571fecb5158d0b, 0xb7c45b6744c71fbb,
            0xff2efcf05d8d8db9, 0x7a585871e5c419c0, 0x6b5c4691b9125e71, 0xa55be7d2b358ec6e,
        ];

        #[rustfmt::skip]
        let k512_2_iv_1: [u64; 8] = [
            0xd2a6103c50bd4e04, 0xdc6a21af5eb13b73, 0xdf4ca6cb07797265, 0xf453c253d8d01876,
            0x039a64dc7a01800c, 0x688ce327dccb7e84, 0x41e0250b5e526403, 0x9936e478aa200f22,
        ];

        #[rustfmt::skip]
        let k512_1_iv_2: [u64; 8] = [
            0xcca12eae8133aaaa, 0x528d85507ce8501d, 0xda83c7fe3e1823f1, 0x21416ebf63b71a42,
            0x26d76d2bf1a625eb, 0xeec66ee0cd0b1efc, 0x02dd68f338a345a8, 0x47538790a5411adb,
        ];

        #[rustfmt::skip]
        let k512_2_iv_2: [u64; 8] = [
            0x965648e775c717d5, 0xa63c2a7376e92df3, 0x0b0eb0bbd47ca267, 0xea593d979ae5bd39,
            0xd773b5e5193cafe1, 0xb0a26671d259422b, 0x85b2aa326b280156, 0x511ace6451435f0c,
        ];

        let cases = [
            (iv_1, k512_1, k512_1_iv_1),
            (iv_1, k512_2, k512_2_iv_1),
            (iv_2, k512_1, k512_1_iv_2),
            (iv_2, k512_2, k512_2_iv_2),
        ];

        for (iv, k, r) in cases {
            let mut z = [0; 64];

            let mut encoder = Dstu8845_512::new_from_slices(&k, &iv).unwrap();
            encoder.apply_keystream(&mut z);

            unsafe {
                assert_eq!(std::mem::transmute::<_, [u64; 8]>(z), r);
            }
        }
    }
}
