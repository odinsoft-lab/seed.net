using System;
using System.Linq;
using System.Text;
using Seed.Net.Cryptography;
using Xunit;

namespace SeedNet.Tests
{
    public class Seed128BasicTests
    {
        private static byte[] Fixed(int seed, int size)
        {
            var rnd = new Random(seed);
            var buf = new byte[size];
            rnd.NextBytes(buf);
            return buf;
        }

        [Fact]
        public void EncryptDecrypt_RoundTrip_WithPadding_CBC()
        {
            var key = Fixed(128, 16);
            var iv = Fixed(256, 16);
            var seed = new Seed128(key, iv);
            seed.Padding = true;

            var plain = Encoding.UTF8.GetBytes("Hello SEED-128! 한글 테스트 😊");
            var enc = seed.Encrypt(plain);
            Assert.NotEqual(plain, enc);

            var dec = seed.Decrypt(enc);
            Assert.Equal(plain, dec);
        }

        [Fact]
        public void EncryptDecrypt_RoundTrip_NoPadding_ECB()
        {
            var key = Fixed(42, 16);
            var iv = Fixed(777, 16); // ignored in no-padding mode
            var seed = new Seed128(key, iv);
            seed.Padding = false; // no padding -> ECB path

            // must be multiple of 16 bytes for no-padding ECB path
            var plain = Enumerable.Range(0, 3)
                .SelectMany(_ => Enumerable.Repeat((byte)0xAB, 16))
                .ToArray();

            var enc = seed.Encrypt(plain);
            Assert.Equal(plain.Length, enc.Length);
            Assert.NotEqual(plain, enc);

            var dec = seed.Decrypt(enc);
            Assert.Equal(plain, dec);
        }

        [Fact]
        public void Base64_Converters_Work()
        {
            var key = Fixed(999, 16);
            var iv = Fixed(555, 16);
            var seed = new Seed128(key, iv);
            seed.Padding = true;

            var text = "PlainText-Base64";
            var chip = seed.PlainStringToChiperBase64(text);
            Assert.False(string.IsNullOrWhiteSpace(chip));

            var back = seed.ChiperBase64ToPlainString(chip);
            Assert.Equal(text, back);

            var chip2 = seed.PlainBytesToChiperBase64(Encoding.UTF8.GetBytes(text));
            Assert.False(string.IsNullOrWhiteSpace(chip2));

            var bytes = seed.ChiperBase64ToPlainBytes(chip2);
            Assert.Equal(Encoding.UTF8.GetBytes(text), bytes);
        }
    }
}
