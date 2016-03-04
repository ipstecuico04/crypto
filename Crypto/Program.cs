using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Crypto
{
    class Program
    {
        static void Main(string[] args)
        {
            TripleDESCSPEncryption();
            AESCSPEncryption();
            HSMEncryption();
        }

        private static void TripleDESCSPEncryption()
        {
            byte[] key = Encoding.UTF8.GetBytes("inputKey_16bytes");
            byte[] inputData = Encoding.UTF8.GetBytes("data to encrypt.");

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();

            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.None;
            tdes.Key = key;

            ICryptoTransform ct = tdes.CreateEncryptor();

            byte[] result = ct.TransformFinalBlock(inputData, 0, inputData.Length);

            tdes.Clear();

            Console.WriteLine(Convert.ToBase64String(result));
        }

        private static void AESCSPEncryption()
        {
            byte[] key = Encoding.UTF8.GetBytes("inputKey_16bytes");
            byte[] inputData = Encoding.UTF8.GetBytes("data to encrypt.");

            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();

            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key;

            ICryptoTransform ct = aes.CreateEncryptor();

            byte[] result = ct.TransformFinalBlock(inputData, 0, inputData.Length);

            aes.Clear();

            Console.WriteLine(Convert.ToBase64String(result));
        }

        private static void HSMEncryption()
        {
            using (Pkcs11 pkcs11 = new Pkcs11("cryptoki.dll", true))
            {
                // Get list of available slots with token present
                List<Slot> slots = pkcs11.GetSlotList(true);

                // Find first slot with token present
                Slot slot = slots[4];

                // Open RO session
                using (Session session = slot.OpenSession(true))
                {
                    session.Login(CKU.CKU_USER, "admin2");

                    // Prepare attribute template that defines search criteria
                    List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, "TestKey"));

                    // Initialize searching
                    session.FindObjectsInit(objectAttributes);

                    // Get search results
                    List<ObjectHandle> foundObjects = session.FindObjects(2);

                    // Terminate searching
                    session.FindObjectsFinal();

                    ObjectHandle objectHandle = foundObjects[0];

                    byte[] iv = Encoding.UTF8.GetBytes("00000000");
                    byte[] inputData = Encoding.UTF8.GetBytes("data to encrypt.");

                    Mechanism mechanism = new Mechanism(CKM.CKM_DES3_CBC, iv);

                    byte[] result = session.Encrypt(mechanism, objectHandle, inputData);

                    Console.WriteLine(Convert.ToBase64String(result)); 
                }
            }
        }

    }
}
