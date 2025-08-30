using System;
using System.Text;

namespace Seed.Net.Cryptography
{
    /// <summary>
    /// SEED-128 block cipher built on top of the base <see cref="Seed"/> utilities.
    /// Provides CBC with PKCS#7-like padding when <see cref="Seed.Padding"/> is true,
    /// and raw ECB without padding when false.
    /// </summary>
    public class Seed128 : Seed
    {
        private const int __pad_size = 16;
        private const int __round_size = 32;

        /// <summary>
        /// SEED-128 is a 128-bit block cipher using a 128-bit symmetric key.
        /// </summary>
        /// <param name="seed_key">16-byte symmetric key.</param>
        /// <param name="seed_iv">16-byte initialization vector (used in CBC mode).</param>
        public Seed128(byte[] seed_key, byte[] seed_iv)
            : base(seed_key, seed_iv)
        {
        }

        /// <summary>
        /// Key schedule update (type 0). Produces two 32-bit subkeys at offset <paramref name="idx"/>.
        /// </summary>
        /// <param name="K">Round key buffer (32 uints).</param>
        /// <param name="idx">Offset into <paramref name="K"/> where the two words are stored.</param>
        /// <param name="A">Key state word A (rotated in-place).</param>
        /// <param name="B">Key state word B (rotated in-place).</param>
        /// <param name="C">Key state word C.</param>
        /// <param name="D">Key state word D.</param>
        /// <param name="KC">Round constant.</param>
        private void RoundKeyUpdate0(ref uint[] K, int idx, ref uint A, ref uint B, ref uint C, ref uint D, uint KC)
        {
            uint T0 = A + C - KC;
            uint T1 = B + KC - D;

            K[0 + idx] = SS0[GetB0(T0)] ^ SS1[GetB1(T0)] ^ SS2[GetB2(T0)] ^ SS3[GetB3(T0)];
            K[1 + idx] = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^ SS2[GetB2(T1)] ^ SS3[GetB3(T1)];

            T0 = A;

            A = (A >> 8) ^ (B << 24);
            B = (B >> 8) ^ (T0 << 24);
        }

        /// <summary>
        /// Key schedule update (type 1). Produces two 32-bit subkeys at offset <paramref name="idx"/>.
        /// </summary>
        /// <param name="K">Round key buffer (32 uints).</param>
        /// <param name="idx">Offset into <paramref name="K"/> where the two words are stored.</param>
        /// <param name="A">Key state word A.</param>
        /// <param name="B">Key state word B.</param>
        /// <param name="C">Key state word C (rotated in-place).</param>
        /// <param name="D">Key state word D (rotated in-place).</param>
        /// <param name="KC">Round constant.</param>
        private void RoundKeyUpdate1(ref uint[] K, int idx, ref uint A, ref uint B, ref uint C, ref uint D, uint KC)
        {
            uint T0 = A + C - KC;
            uint T1 = B + KC - D;

            K[0 + idx] = SS0[GetB0(T0)] ^ SS1[GetB1(T0)] ^ SS2[GetB2(T0)] ^ SS3[GetB3(T0)];
            K[1 + idx] = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^ SS2[GetB2(T1)] ^ SS3[GetB3(T1)];

            T0 = C;

            C = (C << 8) ^ (D >> 24);
            D = (D << 8) ^ (T0 >> 24);
        }

        /// <summary>
        /// Derive 32 32-bit round keys from the 128-bit user key.
        /// </summary>
        /// <param name="pRoundKey">Output buffer that receives the round keys (length 32).</param>
        /// <param name="UserKey">Input 16-byte user key.</param>
        private void SeedEncRoundKey(ref uint[] pRoundKey, byte[] UserKey)
        {
            uint A, B, C, D;                    // Iuput/output values at each rounds
            uint T0, T1;                        // Temporary variable
            uint[] K = pRoundKey;               // Pointer of round keys

            // Set up input values for Key Schedule
            A = BitConverter.ToUInt32(UserKey, 0);
            B = BitConverter.ToUInt32(UserKey, 4);
            C = BitConverter.ToUInt32(UserKey, 8);
            D = BitConverter.ToUInt32(UserKey, 12);

            // Reorder for big endian
            A = EndianChange(A);
            B = EndianChange(B);
            C = EndianChange(C);
            D = EndianChange(D);

            // i-th round keys( K_i,0 and K_i,1 ) are denoted as K[2*(i-1)] and K[2*i-1], respectively
            RoundKeyUpdate0(ref K, 0, ref A, ref B, ref C, ref D, KC0);              // K_1,0 and K_1,1
            RoundKeyUpdate1(ref K, 2, ref A, ref B, ref C, ref D, KC1);              // K_2,0 and K_2,1
            RoundKeyUpdate0(ref K, 4, ref A, ref B, ref C, ref D, KC2);              // K_3,0 and K_3,1
            RoundKeyUpdate1(ref K, 6, ref A, ref B, ref C, ref D, KC3);              // K_4,0 and K_4,1
            RoundKeyUpdate0(ref K, 8, ref A, ref B, ref C, ref D, KC4);              // K_5,0 and K_5,1
            RoundKeyUpdate1(ref K, 10, ref A, ref B, ref C, ref D, KC5);             // K_6,0 and K_6,1
            RoundKeyUpdate0(ref K, 12, ref A, ref B, ref C, ref D, KC6);             // K_7,0 and K_7,1
            RoundKeyUpdate1(ref K, 14, ref A, ref B, ref C, ref D, KC7);             // K_8,0 and K_8,1
            RoundKeyUpdate0(ref K, 16, ref A, ref B, ref C, ref D, KC8);             // K_9,0 and K_9,1
            RoundKeyUpdate1(ref K, 18, ref A, ref B, ref C, ref D, KC9);             // K_10,0 and K_10,1
            RoundKeyUpdate0(ref K, 20, ref A, ref B, ref C, ref D, KC10);            // K_11,0 and K_11,1
            RoundKeyUpdate1(ref K, 22, ref A, ref B, ref C, ref D, KC11);            // K_12,0 and K_12,1
            RoundKeyUpdate0(ref K, 24, ref A, ref B, ref C, ref D, KC12);            // K_13,0 and K_13,1
            RoundKeyUpdate1(ref K, 26, ref A, ref B, ref C, ref D, KC13);            // K_14,0 and K_14,1
            RoundKeyUpdate0(ref K, 28, ref A, ref B, ref C, ref D, KC14);            // K_15,0 and K_15,1

            T0 = A + C - KC15;
            T1 = B - D + KC15;
            K[30] = SS0[GetB0(T0)] ^ SS1[GetB1(T0)] ^ SS2[GetB2(T0)] ^ SS3[GetB3(T0)];  // K_16,0
            K[31] = SS0[GetB0(T1)] ^ SS1[GetB1(T1)] ^ SS2[GetB2(T1)] ^ SS3[GetB3(T1)];  // K_16,1
        }

        /// <summary>
        /// Encrypt a single 16-byte block in-place using the provided round keys.
        /// </summary>
        /// <param name="pData">Block to be encrypted (length 16).</param>
        /// <param name="RoundKey">Round keys produced by the key schedule.</param>
        private void SeedEncryptBlock(ref byte[] pData, uint[] RoundKey)
        {
            uint L0, L1, R0, R1;                    // Iuput/output values at each rounds
            //uint T0, T1;                            // Temporary variables for round function F
            uint[] K = RoundKey;                    // Pointer of round keys

            // Set up input values for first round
            L0 = BitConverter.ToUInt32(pData, 0);
            L1 = BitConverter.ToUInt32(pData, 4);
            R0 = BitConverter.ToUInt32(pData, 8);
            R1 = BitConverter.ToUInt32(pData, 12);

            // Reorder for big endian (matches the reference algorithm behavior)
            L0 = EndianChange(L0);
            L1 = EndianChange(L1);
            R0 = EndianChange(R0);
            R1 = EndianChange(R1);

            SeedRound(ref L0, ref L1, R0, R1, K, 0);
            SeedRound(ref R0, ref R1, L0, L1, K, 2);
            SeedRound(ref L0, ref L1, R0, R1, K, 4);
            SeedRound(ref R0, ref R1, L0, L1, K, 6);
            SeedRound(ref L0, ref L1, R0, R1, K, 8);
            SeedRound(ref R0, ref R1, L0, L1, K, 10);
            SeedRound(ref L0, ref L1, R0, R1, K, 12);
            SeedRound(ref R0, ref R1, L0, L1, K, 14);
            SeedRound(ref L0, ref L1, R0, R1, K, 16);
            SeedRound(ref R0, ref R1, L0, L1, K, 18);
            SeedRound(ref L0, ref L1, R0, R1, K, 20);
            SeedRound(ref R0, ref R1, L0, L1, K, 22);
            SeedRound(ref L0, ref L1, R0, R1, K, 24);
            SeedRound(ref R0, ref R1, L0, L1, K, 26);
            SeedRound(ref L0, ref L1, R0, R1, K, 28);
            SeedRound(ref R0, ref R1, L0, L1, K, 30);

            L0 = EndianChange(L0);
            L1 = EndianChange(L1);
            R0 = EndianChange(R0);
            R1 = EndianChange(R1);

            // Copy output values from the last round to pData
            Buffer.BlockCopy(BitConverter.GetBytes(R0), 0, pData, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(R1), 0, pData, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(L0), 0, pData, 8, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(L1), 0, pData, 12, 4);
        }

        /// <summary>
        /// Decrypt a single 16-byte block in-place using the provided round keys (reverse order).
        /// </summary>
        /// <param name="pData">Block to be decrypted (length 16).</param>
        /// <param name="RoundKey">Round keys produced by the key schedule.</param>
        private void SeedDecryptBlock(ref byte[] pData, uint[] RoundKey)
        {
            uint L0, L1, R0, R1;                    // Iuput/output values at each rounds
            //uint T0, T1;                            // Temporary variables for round function F
            uint[] K = RoundKey;                    // Pointer of round keys

            // Set up input values for first round
            L0 = BitConverter.ToUInt32(pData, 0);
            L1 = BitConverter.ToUInt32(pData, 4);
            R0 = BitConverter.ToUInt32(pData, 8);
            R1 = BitConverter.ToUInt32(pData, 12);

            // Reorder for big endian
            L0 = EndianChange(L0);
            L1 = EndianChange(L1);
            R0 = EndianChange(R0);
            R1 = EndianChange(R1);

            SeedRound(ref L0, ref L1, R0, R1, K, 30);
            SeedRound(ref R0, ref R1, L0, L1, K, 28);
            SeedRound(ref L0, ref L1, R0, R1, K, 26);
            SeedRound(ref R0, ref R1, L0, L1, K, 24);
            SeedRound(ref L0, ref L1, R0, R1, K, 22);
            SeedRound(ref R0, ref R1, L0, L1, K, 20);
            SeedRound(ref L0, ref L1, R0, R1, K, 18);
            SeedRound(ref R0, ref R1, L0, L1, K, 16);
            SeedRound(ref L0, ref L1, R0, R1, K, 14);
            SeedRound(ref R0, ref R1, L0, L1, K, 12);
            SeedRound(ref L0, ref L1, R0, R1, K, 10);
            SeedRound(ref R0, ref R1, L0, L1, K, 8);
            SeedRound(ref L0, ref L1, R0, R1, K, 6);
            SeedRound(ref R0, ref R1, L0, L1, K, 4);
            SeedRound(ref L0, ref L1, R0, R1, K, 2);
            SeedRound(ref R0, ref R1, L0, L1, K, 0);

            L0 = EndianChange(L0);
            L1 = EndianChange(L1);
            R0 = EndianChange(R0);
            R1 = EndianChange(R1);

            // Copy output values from the last round to pData
            Buffer.BlockCopy(BitConverter.GetBytes(R0), 0, pData, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(R1), 0, pData, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(L0), 0, pData, 8, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(L1), 0, pData, 12, 4);
        }

        /// <summary>
        /// Encrypt an arbitrary byte array.
        /// When <see cref="Seed.Padding"/> is true, applies PKCS#7-like padding and CBC chaining.
        /// When false, processes data as ECB without padding; input length must be a multiple of 16 bytes.
        /// </summary>
        /// <param name="plain_data">Plaintext bytes.</param>
        /// <returns>Ciphertext bytes.</returns>
        public byte[] Encrypt(byte[] plain_data)
        {
            var _inp_size = plain_data.Length;

            var _out_size = (int)(_inp_size / __pad_size) * __pad_size;
            if (base.Padding == true)
                _out_size = (int)((_inp_size + __pad_size) / __pad_size) * __pad_size;

            var _out_data = new byte[_out_size];
            Buffer.BlockCopy(plain_data, 0, _out_data, 0, _inp_size);

            if (base.Padding == true)
            {
                var _padding = _out_size - _inp_size;
                if (_padding == 0)
                    _padding = __pad_size;

                for (int i = _inp_size; i < _out_size; i++)
                    _out_data[i] = Convert.ToByte(_padding);
            }

            var _round_key = new uint[__round_size];
            SeedEncRoundKey(ref _round_key, base.Key);

            // CBC initial value (IV)
            var _prev_data = new byte[__pad_size];
            if (base.IV != null && base.IV.Length > 0)
                Buffer.BlockCopy(base.IV, 0, _prev_data, 0, __pad_size);

            for (int i = 0; i < _out_size; i += __pad_size)
            {
                var _data_block = new byte[__pad_size];
                Buffer.BlockCopy(_out_data, i, _data_block, 0, __pad_size);

                if (base.Padding == true)
                    XorByte(ref _data_block, _prev_data);

                SeedEncryptBlock(ref _data_block, _round_key);

                Buffer.BlockCopy(_data_block, 0, _out_data, i, __pad_size);

                if (base.Padding == true)
                    Buffer.BlockCopy(_data_block, 0, _prev_data, 0, __pad_size);
            }

            return _out_data;
        }

        /// <summary>
        /// Decrypt an arbitrary byte array.
        /// When <see cref="Seed.Padding"/> is true, performs CBC de-chaining and removes padding.
        /// When false, processes data as ECB without padding; input length must be a multiple of 16 bytes.
        /// </summary>
        /// <param name="encrypted_data">Ciphertext bytes.</param>
        /// <returns>Recovered plaintext bytes.</returns>
        public byte[] Decrypt(byte[] encrypted_data)
        {
            var _out_size = encrypted_data.Length;

            var _out_data = new byte[_out_size];

            var _round_key = new uint[__round_size];
            SeedEncRoundKey(ref _round_key, base.Key);

            // CBC initial value (IV)
            var _prev_data = new byte[__pad_size];
            if (base.IV != null && base.IV.Length > 0)
                Buffer.BlockCopy(base.IV, 0, _prev_data, 0, __pad_size);

            for (int i = 0; i < _out_size; i += __pad_size)
            {
                var _data_block = new byte[__pad_size];
                Buffer.BlockCopy(encrypted_data, i, _data_block, 0, __pad_size);

                SeedDecryptBlock(ref _data_block, _round_key);

                if (base.Padding == true)
                    XorByte(ref _data_block, _prev_data);

                Buffer.BlockCopy(_data_block, 0, _out_data, i, __pad_size);

                if (base.Padding == true)
                    Buffer.BlockCopy(encrypted_data, i, _prev_data, 0, __pad_size);
            }

            if (base.Padding == true)
            {
                var _padding = _out_data[_out_size - 1];
                if (_padding > 0 && _padding <= __pad_size)
                {
                    var i = 0;

                    for (i = _out_size - 1; i > _out_size - _padding; i--)
                    {
                        if (_out_data[i] != _padding)
                            break;
                    }

                    if (i == _out_size - _padding)
                    {
                        _out_size -= _padding;
                        Buffer.BlockCopy(_out_data, 0, encrypted_data, 0, _out_size);

                        _out_data = new byte[_out_size];
                        Buffer.BlockCopy(encrypted_data, 0, _out_data, 0, _out_size);
                    }
                }
            }

            return _out_data;
        }

        /// <summary>
        /// Convert a plain Base64 string to an encrypted Base64 string.
        /// Useful when the caller already has base64-encoded input.
        /// </summary>
        /// <param name="plain_text">Base64-encoded plaintext.</param>
        /// <returns>Base64-encoded ciphertext.</returns>
        public string PlainBase64ToChiperBase64(string plain_text)
        {
            return Convert.ToBase64String(this.Encrypt(Convert.FromBase64String(plain_text)));
        }

        /// <summary>
        /// Convert an encrypted Base64 string to a plain Base64 string.
        /// </summary>
        /// <param name="chiper_text">Base64-encoded ciphertext.</param>
        /// <returns>Base64-encoded plaintext.</returns>
        public string ChiperBase64ToPlainBase64(string chiper_text)
        {
            return Convert.ToBase64String(this.Decrypt(Convert.FromBase64String(chiper_text)));
        }

        /// <summary>
        /// Convert plain bytes to an encrypted Base64 string.
        /// </summary>
        /// <param name="plain_data">Plaintext bytes.</param>
        /// <returns>Base64-encoded ciphertext.</returns>
        public string PlainBytesToChiperBase64(byte[] plain_data)
        {
            return Convert.ToBase64String(this.Encrypt(plain_data));
        }

        /// <summary>
        /// Convert an encrypted Base64 string to plain bytes.
        /// </summary>
        /// <param name="chiper_text">Base64-encoded ciphertext.</param>
        /// <returns>Plaintext bytes.</returns>
        public byte[] ChiperBase64ToPlainBytes(string chiper_text)
        {
            return this.Decrypt(Convert.FromBase64String(chiper_text));
        }

        /// <summary>
        /// Convert a plain string to an encrypted Base64 string.
        /// </summary>
        /// <param name="plain_text">Plain string (encoded using system default codepage).</param>
        /// <returns>Base64-encoded ciphertext.</returns>
        public string PlainStringToChiperBase64(string plain_text)
        {
            return Convert.ToBase64String(this.Encrypt(Encoding.Default.GetBytes(plain_text)));
        }

        /// <summary>
        /// Convert an encrypted Base64 string to a plain string.
        /// </summary>
        /// <param name="chiper_text">Base64-encoded ciphertext.</param>
        /// <returns>UTF-8 decoded plaintext string.</returns>
        public string ChiperBase64ToPlainString(string chiper_text)
        {
            return Encoding.UTF8.GetString(this.Decrypt(Convert.FromBase64String(chiper_text)));
        }

        /// <summary>
        /// Convert a plain string to an encrypted string (cipher bytes re-interpreted as UTF-8 for demo).
        /// Note: for safe transport, prefer Base64 methods.
        /// </summary>
        /// <param name="plain_text">Plain string (encoded using system default codepage).</param>
        /// <returns>UTF-8 decoded string of ciphertext bytes (not portable).</returns>
        public string PlainStringToChiperString(string plain_text)
        {
            return Encoding.UTF8.GetString(this.Encrypt(Encoding.Default.GetBytes(plain_text)));
        }

        /// <summary>
        /// Convert an encrypted string to a plain string.
        /// </summary>
        /// <param name="chiper_text">Ciphertext as a raw string (UTF-8 decode of bytes).</param>
        /// <returns>UTF-8 decoded plaintext string.</returns>
        public string ChiperStringToPlainString(string chiper_text)
        {
            return Encoding.UTF8.GetString(this.Decrypt(Encoding.Default.GetBytes(chiper_text)));
        }
    }
}