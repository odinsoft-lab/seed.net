namespace Seed.Security.Cryptography.Test
{
    internal class Program
    {
        static string RsaEncryptTest(byte[] symmetry_key)
        {
            RsaEncryption rsa = new RsaEncryption();
            // You can inspect the public key if needed for interop testing.
            // Console.WriteLine($"Public key: {rsa.GetPublicKey()} \n");

            var cypher = rsa.Encrypt(symmetry_key);
            return cypher;
        }

        static (string cypher, byte[] key) Seed128Test(string password)
        {
            var _seed_key = new byte[16];
            (new Random(128)).NextBytes(_seed_key);

            var _seed_iv = new byte[16];
            (new Random(128)).NextBytes(_seed_iv);

            var __seed = new Seed128(_seed_key, _seed_iv);

            var _cypher = __seed.PlainStringToChiperBase64(password);
            return (_cypher, __seed.Key);
        }

        static void Main(string[] args)
        {
            var _seed_cypher = Program.Seed128Test("1234");
            Console.WriteLine($"seed cypher: {_seed_cypher.cypher}");
            Console.WriteLine($"length: {_seed_cypher.cypher.Length}");
            Console.WriteLine();

            var _rsa_cypher = Program.RsaEncryptTest(_seed_cypher.key);

            Console.WriteLine($"rsa cypher: {_rsa_cypher}");
            Console.WriteLine($"length: {_rsa_cypher.Length}");
            Console.ReadLine();
        }
    }
}