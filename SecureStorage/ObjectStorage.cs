using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.IsolatedStorage;

//This library exposes methods for saving objects safely in the protected space

namespace SecureStorage
{
    /// <summary>
    /// This class has been conceived to be able to save objects in a safe way, that is: The saved data of any application cannot be considered safe if it will be accessible in clear text to other applications or resident software. For encryption to be active, the library must be initialized using the Initializer class, enabling encryption (encryption is enabled by default).
    /// </summary>
    public class ObjectStorage
    {
        public ObjectStorage(Initializer secureStorage) => _secureStorage = secureStorage;
        private readonly Initializer _secureStorage;

        private string objExtension() => _secureStorage.Encrypyed ? ".cry" : ".xml";
        const string _charNotAllowed = "*?/\\|<>'\"";
        private string ObjFolder(object obj)
        {
            if (obj == null)
            {
                //Debugger.Break();
                throw new ArgumentException("obj null", "");
            }
            return ObjFolder(obj.GetType());
        }
        private string FileName(string objFolder, string key) => Path.Combine(_secureStorage.Domain, objFolder, key) + objExtension();
        private string DirectoryName(string objFolder) => Path.Combine(_secureStorage.Domain, objFolder);
        private static string ObjFolder(Type type)
        {
            var objFolder = type.FullName;
            if (objFolder.Contains("Version="))
            {
                objFolder = type.Namespace + "+" + type.Name;
            }
            return Clear(objFolder);
        }
        /// <summary>
        /// This method is used to encrypt and securely save objects with their public properties. Only public properties will be saved via serializations, so it is important that the class has a parameterless constructor for deserialization.In case the class has only parameterized constructors, it will be necessary to add an empty parameterless constructor, otherwise the deserialization fails.
        /// </summary>
        /// <param name="obj">Object to save</param>
        /// <param name="key">Key used to save the object. This key will be used to upload the object in the future</param>
        /// <returns>The key used to save the object</returns>
        /// <exception cref="ArgumentException">Object to save</exception>
        public string SaveObject(object obj, string key)
        {
#if DEBUG
            if (!Initializer.Initialized)
                Debugger.Break(); // The library was not initialized !!
#endif
            if (key == null || key.IndexOfAny(_charNotAllowed.ToCharArray()) != -1)
            {
                Debugger.Break();//Invalid character in the key
                throw new ArgumentException("Invalid character in the key", "");
            }
            Serialize(obj, key);
            return key;
        }

        /// <summary>
        /// This method is used to load a previously saved object.
        /// </summary>
        /// <param name="type">The type of the object you want to load. Represents type declarations: class types, interface types, array types, value types, enumeration types, type parameters, generic type definitions, and open or closed constructed generic types</param>
        /// <param name="key">The key that was used to save the object</param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public object LoadObject(Type type, string key)
        {
#if DEBUG
            if (!Initializer.Initialized)
                Debugger.Break(); // The library was not initialized !!
#endif
            if (key == null || key.IndexOfAny(_charNotAllowed.ToCharArray()) != -1)
            {
                Debugger.Break();//Invalid character in the key
                throw new ArgumentException("Invalid character in the key", "");
            }
            object obj;
            if (type == null)
            {
                Debugger.Break();//Type is null
                throw new ArgumentException("Type is null", "");
            }
            else
            {
                obj = Deserialize(key, type);
            }
            return obj;
        }
        /// <summary>
        /// Get all the keys used to save a certain type of objects.
        /// </summary>
        /// <param name="type">The type of object whose keys you want to get</param>
        /// <returns>The keys used to save the object</returns>
        public string[] GetAllKey(Type type)
        {
            var result = new List<string>();
            var objFolder = ObjFolder(type);
            if (_secureStorage.IsoStore.DirectoryExists(DirectoryName(objFolder)))
            {
                var files = _secureStorage.IsoStore.GetFileNames(Path.Combine(DirectoryName(objFolder), "*" + objExtension()));
                foreach (var file in files)
                    result.Add(file.Substring(0, file.Length - 4));
            }
            return result.ToArray();
        }

        public object[] GetAllObjects(Type type)
        {
            var result = new List<object>();
            var keys = GetAllKey(type);
            foreach (var key in keys)
            {
                var obj = LoadObject(type, key);
                if (obj != null)
                    result.Add(obj);
            }
            return result.ToArray();
        }

        public void DeleteObject(Type type, string key)
        {
            var objFolder = ObjFolder(type);
            if (_secureStorage.IsoStore.FileExists(FileName(objFolder, key)))
                _secureStorage.IsoStore.DeleteFile(FileName(objFolder, key));
        }

        public void DeleteAllObject(Type type)
        {
            var keys = GetAllKey(type);
            foreach (var key in keys)
            {
                var objFolder = ObjFolder(type);
                if (_secureStorage.IsoStore.FileExists(FileName(objFolder, key)))
                    _secureStorage.IsoStore.DeleteFile(FileName(objFolder, key));
            }
        }

        private static string Clear(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            string functionReturnValue = null;
            foreach (var chr in text.ToCharArray())
            {
                if (_charNotAllowed.IndexOf(chr) != -1)
                    functionReturnValue += "-";
                else
                    functionReturnValue += chr;
            }
            if (functionReturnValue.Length > 255)
            {
                Debugger.Break();
                throw new ArgumentException("File name too long", "");
            }
            return functionReturnValue;
        }

        private void Serialize(object obj, string key)
        {
            try
            {
                lock (_secureStorage.IsoStore)
                {
                    var objFolder = ObjFolder(obj);
                    var fileName = FileName(objFolder, key);
                    if (!_secureStorage.IsoStore.DirectoryExists(DirectoryName(objFolder)))
                        _secureStorage.IsoStore.CreateDirectory(DirectoryName(objFolder));
#if !DEBUG
					try
					{
#endif
                    using (var stream = new IsolatedStorageFileStream(fileName, FileMode.Create, FileAccess.Write, _secureStorage.IsoStore))
                    {
                        var serializer = new System.Xml.Serialization.XmlSerializer(obj.GetType());
                        if (_secureStorage.Encrypyed)
                            using (var memoryStream = new MemoryStream())
                            {
                                serializer.Serialize(memoryStream, obj);
                                var bytes = memoryStream.ToArray();
                                var encryptBytes = Cryptography.Encrypt(bytes, _secureStorage.CryptKey(key));
                                //#if DEBUG
                                //								var xml1 = Encoding.ASCII.GetString(bytes);
                                //								var decript = Cryptography.Decrypt(encryptBytes, _secureStorage.CryptKey(key));
                                //								var xml2 = Encoding.ASCII.GetString(decript);
                                //								var checkObj = serializer.Deserialize(new MemoryStream(bytes));
                                //								if (xml1 != xml2)
                                //									Debugger.Break();
                                //#endif
                                stream.Write(encryptBytes, 0, encryptBytes.Length);
                            }
                        else
                            serializer.Serialize(stream, obj);
                    }
#if !DEBUG
						}
						catch (Exception ex)
						{
							Debug.WriteLine(ex.Message);
							Debugger.Break();
						}
#endif
                }
            }
            catch (Exception ex)
            {
                Debugger.Break();
                Debug.WriteLine(ex.Message);
            }
        }

        private object Deserialize(string key, Type type)
        {
            var objFolder = ObjFolder(type);
            var fileName = FileName(objFolder, key);
            if (!_secureStorage.IsoStore.FileExists(fileName)) return null;
            object obj = null;
            try
            {
                using (Stream stream = new IsolatedStorageFileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.Inheritable, _secureStorage.IsoStore))
                {
                    var serializer = new System.Xml.Serialization.XmlSerializer(type);
                    if (_secureStorage.Encrypyed)
                        using (var memoryStream = new MemoryStream())
                        {
                            stream.CopyTo(memoryStream);
                            var bytes = memoryStream.ToArray();
                            try
                            {
                                bytes = Cryptography.Decrypt(bytes, _secureStorage.CryptKey(key));
                            }
                            catch (Exception)
                            {
                                // If it happens here, it means that data is saved with a different decryption key.
                                // Uninstalling does not remove this data, so it will be deleted!				
                                stream?.Dispose();
                                _secureStorage.IsoStore.DeleteFile(fileName);
                                return null;
                            }
                            obj = serializer.Deserialize(new MemoryStream(bytes));
                        }
                    else
                        obj = serializer.Deserialize(stream);
                }
                //   stream?.Dispose();
            }
            catch (Exception ex)
            {
#if DEBUG
                Debug.WriteLine(ex.InnerException); // Probably some properties of the object class are not serializable. Use [XmlIgnore] to exclude it.
                Debugger.Break();
                _secureStorage.IsoStore.DeleteFile(fileName);
#endif
            }
            return obj;
        }
    }
}