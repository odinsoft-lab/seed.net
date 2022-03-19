using System;
using System.Text;

namespace OdinSoft.Security.Cryptography
{
    /// <summary>
    ///
    /// </summary>
    public class Seed128 : Seed
    {
        private const int __pad_size = 16;
        private const int __round_size = 32;

        /// <summary>
        /// SEED 암호화는 32바이트 대칭키 암호화입니다
        /// </summary>
        /// <param name="seed_key"></param>
        /// <param name="seed_iv"></param>
        public Seed128(byte[] seed_key, byte[] seed_iv)
            : base(seed_key, seed_iv)
        {
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="K"></param>
        /// <param name="idx"></param>
        /// <param name="A"></param>
        /// <param name="B"></param>
        /// <param name="C"></param>
        /// <param name="D"></param>
        /// <param name="KC"></param>
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
        ///
        /// </summary>
        /// <param name="K"></param>
        /// <param name="idx"></param>
        /// <param name="A"></param>
        /// <param name="B"></param>
        /// <param name="C"></param>
        /// <param name="D"></param>
        /// <param name="KC"></param>
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
        /// Encryption Key Schedule
        /// </summary>
        /// <param name="pRoundKey">[out] round keys for encryption or decryption</param>
        /// <param name="UserKey">[in] secret user key</param>
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
        /// Block Encryption
        /// </summary>
        /// <param name="pData">[in,out] data to be encrypted</param>
        /// <param name="RoundKey">[in] round keys for encryption</param>
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

            // Reorder for big endian
            // Because SEED use little endian order in default
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

            // Copying output values from last round to pbData
            Buffer.BlockCopy(BitConverter.GetBytes(R0), 0, pData, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(R1), 0, pData, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(L0), 0, pData, 8, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(L1), 0, pData, 12, 4);
        }

        /// <summary>
        /// Same as encrypt, except that round keys are applied in reverse order
        /// </summary>
        /// <param name="pData">[in,out] data to be decrypted</param>
        /// <param name="RoundKey">[in] round keys for decryption</param>
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

            // Copy output values from last round to pbData
            Buffer.BlockCopy(BitConverter.GetBytes(R0), 0, pData, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(R1), 0, pData, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(L0), 0, pData, 8, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(L1), 0, pData, 12, 4);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="plain_data"></param>
        /// <returns></returns>
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

            // CBC 모드 초기값 IV
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
        ///
        /// </summary>
        /// <param name="encrypted_data"></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] encrypted_data)
        {
            var _out_size = encrypted_data.Length;

            var _out_data = new byte[_out_size];

            var _round_key = new uint[__round_size];
            SeedEncRoundKey(ref _round_key, base.Key);

            // CBC 모드 초기값 IV
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
        /// 평문 Base64 문자열을 암호화된 Base64 문자열로 변환 합니다.
        /// </summary>
        /// <param name="plain_text">plain text</param>
        /// <returns></returns>
        public string PlainBase64ToChiperBase64(string plain_text)
        {
            return Convert.ToBase64String(this.Encrypt(Convert.FromBase64String(plain_text)));
        }

        /// <summary>
        /// 암호화된 Base64 문자열을 평문 Base64 문자열로 변환 합니다.
        /// </summary>
        /// <param name="chiper_text">chiper text</param>
        /// <returns></returns>
        public string ChiperBase64ToPlainBase64(string chiper_text)
        {
            return Convert.ToBase64String(this.Decrypt(Convert.FromBase64String(chiper_text)));
        }

        /// <summary>
        /// 평문 바이트 배열을 암호화된 Base64 문자열로 변환 합니다.
        /// </summary>
        /// <param name="plain_data"></param>
        /// <returns></returns>
        public string PlainBytesToChiperBase64(byte[] plain_data)
        {
            return Convert.ToBase64String(this.Encrypt(plain_data));
        }

        /// <summary>
        /// 암호화된 Base64 문자열을 평문 바이트 배열로 변환 합니다.
        /// </summary>
        /// <param name="chiper_text">chiper text</param>
        /// <returns></returns>
        public byte[] ChiperBase64ToPlainBytes(string chiper_text)
        {
            return this.Decrypt(Convert.FromBase64String(chiper_text));
        }

        /// <summary>
        /// 평문 문자열을 암호화된 Base64 문자열로 변환 합니다.
        /// </summary>
        /// <param name="plain_text">plain text</param>
        /// <returns></returns>
        public string PlainStringToChiperBase64(string plain_text)
        {
            return Convert.ToBase64String(this.Encrypt(Encoding.Default.GetBytes(plain_text)));
        }

        /// <summary>
        /// 암호화된 Base64 문자열을 평문 문자열로 변환 합니다.
        /// </summary>
        /// <param name="chiper_text">chiper text</param>
        /// <returns></returns>
        public string ChiperBase64ToPlainString(string chiper_text)
        {
            return Encoding.UTF8.GetString(this.Decrypt(Convert.FromBase64String(chiper_text)));
        }

        /// <summary>
        /// 평문 문자열을 암호화된 문자열로 변환 합니다.
        /// </summary>
        /// <param name="plain_text">plain text</param>
        /// <returns></returns>
        public string PlainStringToChiperString(string plain_text)
        {
            return Encoding.UTF8.GetString(this.Encrypt(Encoding.Default.GetBytes(plain_text)));
        }

        /// <summary>
        /// 암호화된 문자열을 평문 문자열로 변환 합니다.
        /// </summary>
        /// <param name="chiper_text">chiper text</param>
        /// <returns></returns>
        public string ChiperStringToPlainString(string chiper_text)
        {
            return Encoding.UTF8.GetString(this.Decrypt(Encoding.Default.GetBytes(chiper_text)));
        }
    }
}