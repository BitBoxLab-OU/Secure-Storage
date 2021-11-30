namespace SecureStorage
{
	public static class Cryptography
	{
		internal static bool Initalialized;

		/// <summary>
		/// Encrypt a sequence of bytes using the Bitcoin cryptographic algorithm
		/// </summary>
		/// <param name="clearBytes">Sequence of bytes to encrypt</param>
		/// <param name="password">Key for encryption</param>
		/// <returns></returns>
		public static byte[] Encrypt(byte[] clearBytes, byte[] password)
		{
			var privateKey = new NBitcoin.Key(password, fCompressedIn: false); // generate a random private key
			var encrypt = privateKey.PubKey.Encrypt(clearBytes);
			return encrypt;
		}

		/// <summary>
		/// Decrypt a sequence of encrypted data with the Encrypt function
		/// </summary>
		/// <param name="cipherBytes">Data to decrypt</param>
		/// <param name="password">Encryption key </param>
		/// <returns></returns>
		public static byte[] Decrypt(byte[] cipherBytes, byte[] password)
		{
			var privateKey = new NBitcoin.Key(password, fCompressedIn: false); // generate a random private key
			return privateKey.Decrypt(cipherBytes);
		}
	}
}
