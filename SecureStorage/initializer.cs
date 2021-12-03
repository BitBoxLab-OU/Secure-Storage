using System;
using System.Text;
using System.Security.Cryptography;
using System.IO.IsolatedStorage;
using System.Diagnostics;
using System.IO;

namespace SecureStorage
{
    public class Initializer
    {
        /// <summary>
        /// Prepares the library for using cryptography. Before using the library, initialization is mandatory!
        /// </summary>
        /// <param name="domain">The domain allows you to use multiple instances of the library. Then use different domains to have multiple instances</param>
        /// <param name="getSecureKeyValue">Function to get keys safely save in hardware.</param>
        /// <param name="setSecureKeyValue">Secure function provided by the hardware to be able to save keys</param>
        /// <param name="encrypted">Enable encryption (by default it is active and it is recommended not to delete it to keep your data safe)</param>
        public Initializer(string domain, Func<string, string> getSecureKeyValue = null, SetKeyKalueSecure setSecureKeyValue = null, bool encrypted = true)
        {
            DataStorage = new DataStorage(this);
            ObjectStorage = new ObjectStorage(this);
            Values = new Values(this);
            Domain = domain;
            if (_baseKey != null)
                return; // Already initialized
            if (setSecureKeyValue != null && getSecureKeyValue != null)
            {
                SetKeyValue = (key, value) => setSecureKeyValue(domain + "." + key, value);
                GetKeyValue = key => getSecureKeyValue(domain + "." + key);
                //Check that saving keys and values are working correctly
#if DEBUG
                try
                {
                    SetKeyValue("test", "test");
                    if (GetKeyValue("test") == "test")
                    {
                        SecureKeyValueCapability = true;
                        SetKeyValue("test", "");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine(ex.ToString());
                    Debugger.Break();
                }
#endif
            }
            if (SecureKeyValueCapability == false)
            {
                var hash = _hashAlgorithm.ComputeHash(Encoding.Unicode.GetBytes(Environment.MachineName + Environment.UserName));
                DefaultEncrypter = new NBitcoin.Key(hash);
                SetKeyValue = (key, value) => SetKeyValue_Default(domain + "." + key, value);
                GetKeyValue = key => GetKeyValue_Default(domain + "." + key);
            }

            Encrypyed = encrypted;
            var baseKey = "";
            var h5 = new byte[5];
            Array.Copy(_hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(Environment.MachineName)), h5, h5.Length);
            var _keyName = BitConverter.ToString(h5).Replace("-", "");
            baseKey = GetKeyValue(_keyName);
            if (string.IsNullOrEmpty(baseKey))
            {
                var rnd = new Random();
                var bytes = new byte[32];
                rnd.NextBytes(bytes);
                baseKey = BitConverter.ToString(bytes);
                baseKey += Environment.MachineName + Environment.UserName;
                var hash = _hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(baseKey));
                baseKey = BitConverter.ToString(hash).Replace("-", "");
                SetKeyValue(_keyName, baseKey);
            }
            _baseKey = new byte[baseKey.Length / 2];
            for (var i = 0; i < baseKey.Length; i += 2)
                _baseKey[i / 2] = Convert.ToByte(baseKey.Substring(i, 2), 16);
            Initialized = true;
        }
        internal static readonly IsolatedStorageFile IsoStore = IsolatedStorageFile.GetStore(IsolatedStorageScope.User | IsolatedStorageScope.Assembly | IsolatedStorageScope.Domain, null, null);
        internal static bool Initialized;
        public bool SecureKeyValueCapability;
        public readonly DataStorage DataStorage;
        public readonly ObjectStorage ObjectStorage;
        public readonly Values Values;
        internal bool Encrypyed = true;
        internal string Domain;
        internal SetKeyKalueSecure SetKeyValue;
        public delegate void SetKeyKalueSecure(string key, string value);
        internal Func<string, string> GetKeyValue;
        // OLD VERSION
        //internal readonly IsolatedStorageFile IsoStore = IsolatedStorageFile.GetStore(IsolatedStorageScope.User, null, null);
        private readonly HashAlgorithm _hashAlgorithm = SHA256.Create();
        private readonly byte[] _baseKey;

        internal byte[] CryptKey(string key)
        {
#if DEBUG
            if (_baseKey == null)
            {
                Debug.WriteLine("Please initialize this library before using it. Use InitializeAsync");
                Debugger.Break();
            }
#endif
            var keyByte = Encoding.ASCII.GetBytes(key);
            var fullKey = new byte[(_baseKey == null ? 0 : _baseKey.Length) + keyByte.Length];
            _baseKey?.CopyTo(fullKey, 0);
            var index = _baseKey == null ? 0 : _baseKey.Length;
            keyByte.CopyTo(fullKey, index);
            var cryptKey = _hashAlgorithm.ComputeHash(fullKey);
            return cryptKey;
        }

        private readonly NBitcoin.Key DefaultEncrypter;
        private void SetKeyValue_Default(string key, string value)
        {
            try
            {
                var fileStream = IsoStore.OpenFile(Path.Combine(".", key), FileMode.Create);
                var buffer = Encoding.Unicode.GetBytes(value);
                var encrypted = DefaultEncrypter.PubKey.Encrypt(buffer);
                fileStream.Write(encrypted, 0, encrypted.Length);
                fileStream.Close();
            }
            catch { }
        }
        private string GetKeyValue_Default(string key)
        {
            string result = null;
            try
            {
                var fileStream = IsoStore.OpenFile(Path.Combine(".", key), FileMode.Open);
                var buffer = new byte[fileStream.Length];
                fileStream.Read(buffer, 0, buffer.Length);
                fileStream.Close();
                var decrypted = DefaultEncrypter.Decrypt(buffer);
                return Encoding.Unicode.GetString(decrypted);
            }
            catch { }
            return result;
        }

    }
}