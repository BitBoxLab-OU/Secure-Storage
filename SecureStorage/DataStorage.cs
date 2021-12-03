using System;
using System.Diagnostics;
using System.IO;
using System.IO.IsolatedStorage;
using System.Runtime.Serialization.Formatters.Binary;
using System.Threading;

namespace SecureStorage
{
	public class DataStorage
	{
		public DataStorage(Initializer secureStorage)
		{
			_secureStorage = secureStorage;
		}
		private Initializer _secureStorage;
		private  string FileName(string key) => Path.Combine(_secureStorage.Domain, key) + ".dat";
		public  void SaveData(byte[] data, string key)
		{
			if (_secureStorage.Encrypyed)
			data = Cryptography.Encrypt(data, _secureStorage.CryptKey(key));
			using (IsolatedStorageFileStream file = Initializer.IsoStore.OpenFile(FileName(key), FileMode.Create))
			{
				file.Write(data, 0, data.Length);
			}
		}
		public  byte[] LoadData(string key)
		{
			var fileName = FileName(key);
			if (!Initializer.IsoStore.FileExists(fileName))
				return null;
			byte[] data;
			using (IsolatedStorageFileStream file = Initializer.IsoStore.OpenFile(fileName, FileMode.Open))
			{
				data = new byte[file.Length];
				file.Read(data, 0, (int)file.Length);
			}		
			if (_secureStorage.Encrypyed)
				data = Cryptography.Decrypt(data, _secureStorage.CryptKey(key));
			return data;
		}

		public  void BinarySerialize(object obj, string key)
		{
			try
			{
				new Thread(() =>
				{
					lock (Initializer.IsoStore)
					{
						try
						{
							using (var stream = new IsolatedStorageFileStream(FileName(key), FileMode.Create, FileAccess.Write, Initializer.IsoStore))
							{
								var formatter = new BinaryFormatter();
								if (_secureStorage.Encrypyed)
									using (var memoryStream = new MemoryStream())
									{
										formatter.Serialize(memoryStream, obj);
										var bytes = memoryStream.ToArray();
										bytes = Cryptography.Encrypt(bytes, _secureStorage.CryptKey(key));
										stream.Write(bytes, 0, bytes.Length);
									}
								else
									formatter.Serialize(stream, obj);
							}
						}
						catch (Exception ex)
						{
							Debug.WriteLine(ex.Message);
							Debugger.Break();
						}
					}
				}).Start();
			}
			catch (Exception ex)
			{
				Debug.WriteLine(ex.Message);
			}
		}

		public  object BinaryDeserialize(string key)
		{
			if (!Initializer.IsoStore.FileExists(FileName(key))) return null;
			object obj = null;
			try
			{
				Stream stream = new IsolatedStorageFileStream(FileName(key), FileMode.Open, FileAccess.Read, FileShare.Inheritable, Initializer.IsoStore);
				try
				{
					var formatter = new BinaryFormatter();
					if (_secureStorage.Encrypyed)
						using (var memoryStream = new MemoryStream())
						{
							stream.CopyTo(memoryStream);
							var bytes = memoryStream.ToArray();
							bytes = Cryptography.Decrypt(bytes, _secureStorage.CryptKey(key));
							obj = formatter.Deserialize(new MemoryStream(bytes));
						}
					else
						obj = formatter.Deserialize(stream);
				}
				catch (Exception)
				{
				}
				stream?.Dispose();
			}
			catch (Exception)
			{
			}
			return obj;
		}
	}
}