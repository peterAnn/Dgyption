namespace Common
{
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Encodings;
    using Org.BouncyCastle.Crypto.Engines;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using System;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Xml.Linq;
    using System.Management;
    public class DGyption
    {
        static string _publicKeyString = @"-----BEGIN PUBLIC KEY-----
                                        MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAud60andd8zZv8dBiiAm7
                                        Lcg07/oPATnMdDsEbd8rFYSB/nlmZrMxoiGL8BZGZKlqbQr4zDegAOJOpfraFyTn
                                        qlccFVyg5x8Z2qpfvSnbaak3LnNyj2r97pW/yaQ217ziv5NgKzzCeQNA8rvBri4a
                                        Qh9xxlfCvIlH/JeQz45aLFYIOuVC7akSQ08kZb+ym8SmvabU6H6CwUhNugt/6s/9
                                        T9DhShAxt4aVevxwVFq4eBZ6X5lXS3YDswOrN7/VEX0R86uISTlX7G57d+d0nnKP
                                        1VhXsUQ7KeOEpc3p/5ktTOdysqkJ+Mg27uVLV2mNW7Kz0UA86xi+JP0uDU46GXFB
                                        RxiX72NV0EZDiRD5Pu1Yt7t9RysjvYMRgHgrT4AhwwP5CkUpXujFrKXiKe5VnanZ
                                        CwwBM9o3+0FBCb5gpYsbvX9e25+uU6Ccv2PHnCG3zVZxfYW/UlNTKhkENVsqWmji
                                        jx80QjQBOigvwPp4GAJvjGyyzwCKcYS2qOIPQm+fS/QJQG7wAN5gGwbjOWnsAiNB
                                        Vln9f91tW2mrejPpC/AGfJpz9GyjBBxCionFSzMuuLhzDhvsbTeuXGqTfPHUhTy4
                                        FqoC9KeEP9O2RXhV9rAIZJLKZ9fkKjE8YNrAZrUEzJGKQk21c+ca0Rf1npZbH3a6
                                        Wa17GMYUu2jdgIp0RkXt3QECAwEAAQ==
                                        -----END PUBLIC KEY-----";
        static string _privateKeyString = @"-----BEGIN ENCRYPTED PRIVATE KEY-----
                                        MIIJjjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIJQB2/YtZXaYCAggA
                                        MBQGCCqGSIb3DQMHBAgmgHyMwWA0TgSCCUhF/rffJDkHhTQTpYe9CKG7erUE7hjx
                                        1PCUaUyJ7J3DuQBecVzno6w2fgfhHkS9nIVhRa/AQ9DeZTZiUzzxxKRBOUdz+vhT
                                        GzeILflmM/uyTRND+RBVmYgnu3qmzPkC3UI5L3a+r5+GbCCpByUd5bUatRKiC7xd
                                        e0oTBGHT/Sgbjqc5QRLksXoM262K9p5OStkA9+j+2O1lWk2quMMOubzemLELBLlc
                                        AufNLtlbj/k1tLi1cInikTwzshDZXgoLyJ/c6TndGfxc2xf3tyBsPCyNVu5rLVLN
                                        BFxEPV8QrV5UD8hSImB5cO3u1uM0RFu87KDNeuAdyaH2RGrGT5exp1/7VM9NxPGE
                                        ZHjI3W7DGTjBPHVljsQGXsYrC1U5uozvFiwGMiuH5lSstqSdjcUwwDb28TAw+Sdc
                                        pEKlfTF/uZBJtpA4KoNh98pD2cbMfoZLkhhcZc/CAyvUYhDdYbOJ0pto/L+SamZ1
                                        RWg++191wK0xzt97dgvy5iA63U8C2uu4VbICFzks0JYbGqiH2eaQTr9UYxXJ+xpL
                                        muWRZswst3oZFpVTC3UG2yqz1y/QboVAAxDG+Fi6iZoKm2brfZZpMRor7LsLL8A6
                                        bviwdb7fg5ayAanVkqJCY//hicYiLEes6HC5/8NLFzjw3hDs6PicsyRCj5m1F1AY
                                        J9x2RDWHKObGRNdDkpnGDsan55hughhQ9n/4vL8BLTeS2+2+mILEC3OFz8O/zOq4
                                        N8j4H85szHSd+8+6H2pCzIQTBr3V7xGo6oRDJpp1duS5rp2tSVas/CpGAgUUWUv9
                                        ciAbzTr/2G9ICmdFGHik7Q5JuFzDsMYc9ywxDZowTcZrJKRfoKIAQMYnXvYLpX/O
                                        AI7jwW2WL9i9paUeJ/l1r5uJktnDJYQe8iD4+OdISgpyH1tira6gdqSU+IpthGnC
                                        elSI88mUAGC2QAOYvKlKAIvHvTkWZwWvrEXn5ALV9mcpCq3VkjbpYau4xSFA+4Qu
                                        HVyg3XWKtEJ/xa8eW6BT4bCXel1XbhTixmF5PnNBLqzMDvJDH2+VTpBf6V9xJRJo
                                        I9zPLKyfZMNxua7gt1xXZOwkOTyCmNY8V6h93Ip8NMXlBGT4H/tc3GEnGe7DHDZa
                                        aa/nSpwJjBxLj0D0UzTo5pHAYUFnVxOo4kCxW3gzIbCz26wj424ow1spRxxzNZ2C
                                        krsNaNdlJORifk5pxf7pVeenT4CxPk8BD6U92sKjmrWbx1BwnX8Ezsxfbys+SDew
                                        yGahRdyf2j177KmzqLy0Xm4CnRfSuC9BZ339CWm15G2i1Q4zMFlqYHMyzmY6K4wO
                                        u+uxMvQtEwxzoROs/27r0AodoMirQjXkf01E5e235n8dNX+qGgrYwASA6Ux1AoBA
                                        WvoHFDaeVOOk1FG8+NQwzzl1ocEunTZdOd232cyalYFqkMa5VuUdV+EvVcwqIjoa
                                        WaM+kw0cn8Ct+vimDo1UC+BkUZx2ZPYzqAPjh0vfommK0l/+CclUP+qfqco8FkH4
                                        muvLEoPZR3CgMX1Uzequ5ZHnE0HN7zsCKS5kkYbggFuK6wc/XjFRu2PYpv63wl76
                                        Ej5XgjdaucSwKhP17PyO7NbzzzTW45uwZDFrVJwjMnm0lkKiSHCeZ3w3ELHld+HN
                                        SAsdkfGGRLU8f/51OF25LLpsyhrW2Zg7gin8rKFPa+TMKGr2JK8oXkyoo2as20dk
                                        Nub04RN1ffWky19lPtOA/Am6wfFkOKL2tFafk0GOemxxQjmvKIba4cxiEIdNBTYy
                                        dEyjV8Lf8ccYelFzsc4AlrVZvAL21lnrO2P4J8k3IGUe7j3T/lsLTCygEN+pC52i
                                        3QUSY+kA7vwRrVT20G6oSmdw7jiK1U6ZEy23U5FVteGstNGzeaJnGh2uew0U3Kh/
                                        emQadQ8m4SoEA1qVpYmQrf6VjoTfHqaw6bmA/fEHpoKZqsYu4WCmCa7oc2v5d0lw
                                        bMMh1EmKcpp/TR7X7g8pzJLQ5FMUwood6kQucsuy+eduaECygVGpsApQH+wj2wav
                                        vq6MMKPl4smCo7pssvDpRgTx9nIl99KReUCiBjVNvFA8udb8EUiRQJSvufahIVgb
                                        Affg73b0kxXnTofGEnPEuBFhjUx3yEsyqCv6hhn19UgCjnASdn99CpD2oIxpEoC0
                                        mTs7CFMpHA3gZB+Db40Z3TM/LWsFuibbv0eI+329IC9i+dzTtvJpF2Bjbm4j7MOU
                                        reDwv7IHy/Tvfh02/sd4iZOTvrfRSYMJa+vEGkRxuiwPDq97qpf29zXIDhoiSslR
                                        I5LfoLji5Txs+FelqRgTrVXJadRpXHzDTqdk8l9YRUYRErWDGxr71/zRlDvUVDbB
                                        IAPwGkLS2/xYbe3jks3tjFCEF3M8ftYChgqVcw2icExLM0IA+Uh9juNWeTEj5vXd
                                        kOhKXULN02FQAwzA/PKPoe8kN8ZPs7Z+lv1TkrYoirVTAfvnwZpYV44txxTwMOkE
                                        gplL1DsnAnqTVFRL7oweMqVuLEvG9pdb5UBfLqyi/1rxHJPgeDaxA6o77SN4yUYe
                                        U4nlIJyxAklH9P5XX4LFwEdOGWfsc4x60yBHi0gPDC0eTj3RnymSN7Q8ROwP6r9Z
                                        O/GalIHUSqMga78WPoc/ukzm0HTpxwJ9wCE56X8lTLKdDxFqaqVOttTY6EqvVL9F
                                        w4cvOv+ITPMDL+AsWj218SU0TBBx0IDhplz/fAGfkVXu2hQ3Y0iP9eayjRZJWBMP
                                        tuJ8v2zLPzebRDpiDKS9UscO7jUOmucdDp0KN6RZU5+BD/WDDU480dvKaypfta5/
                                        WcSA1xvHcrS+csiz1mO2nmdWuAREeyy55zmahKu7Z42VBsNk1aC3tw9OSd/8mxHE
                                        OnGiqlraqUxgBFBVU8CPwBIWzbFRu33f5NT4Ep5QA7OgEYM0FyvOV/kTqsTqinlH
                                        HQsyra9azOnaaqCkbvDRG0ab7YMql4AF86iCj54Wr4qZvohiKac6rZfLrOaVo/wI
                                        E3RtGjmxZRqwn0qtFegU7Wu7amgoI5Jod6c3NkOMYjju8Ol/E0lexgFPg9BaFBx8
                                        feSMdXXGfn61CZUk2JAfdZrEuF8nr3eL69DiKagio5dajL1t6yBNvfJhjvDg2qDy
                                        7XHVWJppdSjojm/jcnPhw9ck9QDS13jDAKUHJjKu7i6YQ9EEaHkseYxQzvO4yrhr
                                        I6M=
                                        -----END ENCRYPTED PRIVATE KEY-----";
         
        static string _publicKeyStringW = @"-----BEGIN PUBLIC KEY-----
                                            MIGfMA0GCSqGSIb3DQNBAQUAA4GNADCBiQKBgQDB1cKYfPD/rtL1c6QbX/vrPkZ6
                                            U0lY2Iiw50d8EQLfKYac7pCW0BPgDxNN5gtUVc7+PNaN7nZM1FDaQJpRdymXlaF0
                                            docgR5bfEaqXQThabSStk+qJgB/gUoCC/wdUdBEm3EZfT/hhGj96OKzy3AIRzLRE
                                            eyBR9lasKK7GFftE/wIDAQAB
                                            -----END PUBLIC KEY-----";

        static  string _privateKeyStringW = @"-----BEGIN ENCRYPTED PRIVATE KEY-----
                                            MIICxjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQITRsDegq6+0YCAggA
                                            MBQGCCqGSIb3DQMHBAj1MeyTfHF7XwSCAoBDHDhwbCNYtMAaWKxbMGklw8hJexnN
                                            Y1w3CWc0BS6OdlBzMR2TGFJji1cOOaw63NGfGQ7eb6cSlfsvt1d3lE3+yN7PYIjz
                                            1ncpyPl1CDTNMbUwAzm5/p++CFiWzSEEUVrEUKNtVi/AqBBTdxi6J0nmQu3XG1qS
                                            qXhV8vZ8fA/c2EysAoVQyUcYUUJDLd4pf6YsOrkC4LGtKsbwV9C7UBp52XG0V8/t
                                            5hBmxA3y2MolNg0g1YGyhhSGJdlpBBZMPz3LMMISik5pFc2EORiAqY1+f7+rcShT
                                            zELplFo+58TXUXKs3QAaZ4DiS056t9OSWxb+6TGtaeW2OUJnTmLbgYX9T53rIx1b
                                            Lyo1+J4G4ySauXhg2qVtluT0Jgm7lcm8KOy73y43nBqnI7UWhqGqycObTeMXcKhz
                                            8d31j9widhn8hbvgMU28NLUr0jfHiKZBVNC7kt79tVGDD68P45vH94tzlmBQFsDy
                                            l2wryoM4F5BjA0e1VavvCC/4am3vg8W+FALfZG+d1/baaMceEmM0O81X7PS9pACY
                                            xeIMAGZqI4HsdbCdVV3SidR0zxxMb4Li+7zNcVqeVZKlpQEc7gsXcfLnGThqf2Kr
                                            XqMhuXNZXl5NNmWOpklegf6j4rI5EiVL8ue74FRrXOhnm6drHip4THUdH6q7h0Zp
                                            E+Cwj1Q0OBMgWIeXLBcutFmEZ5wo3AC77jiP5siHNZLLZW4Z6CAyCtOsr/mWLpzL
                                            skDSJ0v9aYQI6Z30hd45vBtaKaOgMK23pquZbIy65wkReA4/DOEspE4YOwEPS9l1
                                            PxKx6J/htetQuMS0ZHABnLTBSPHYQQmRCqdrnyMseNMp/7pDgG55aPnq
                                            -----END ENCRYPTED PRIVATE KEY-----";


        public int KeyLenght { get; set; } = 4096;

        private class PasswordFinder : IPasswordFinder
        {
            private char[] password;

            public PasswordFinder(char[] word)
            {
                this.password = (char[])word.Clone();
            }

            public char[] GetPassword()
            {
                return (char[])password.Clone();
            }
        }

        public static string RsaEncryptWithPrivate(string dataToEncrypt)
        {
            try
            {
                var bytesToEncrypt = Encoding.UTF8.GetBytes(dataToEncrypt);
                var encryptEngine = new Pkcs1Encoding(new RsaEngine());
                using (var txtReader = new StringReader(_privateKeyString))
                {
                    var keyPair = (AsymmetricCipherKeyPair)new PemReader(txtReader, new PasswordFinder("trdfdsfsd@12311".ToCharArray())).ReadObject();
                    encryptEngine.Init(true, keyPair.Private);
                }
                var encryptedText = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
                
                return encryptedText;
            }
            catch
            {
                return dataToEncrypt;
            }
            
        }
        public static string RsaDecryptWithPrivate(string dataToDecrypt)
        {
            try
            {
                var bytesToDecrypt = Convert.FromBase64String(dataToDecrypt);

                var stringReader = new StringReader(_privateKeyString);
                var pemReader = new PemReader(stringReader, new PasswordFinder("trdfdsfsd@12311".ToCharArray()));
                var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                var keyParameter = keyPair.Private;

                IBufferedCipher cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
                cipher.Init(false, keyParameter);
                var decipheredBytes = cipher.DoFinal(bytesToDecrypt);

                var decipheredText = Encoding.UTF8.GetString(decipheredBytes);
                if (VerifyPcSign() == false) //illegal
                {
                    return HMACSHA1Encode(dataToDecrypt);
                }
                return dataToDecrypt;
            }
            catch
            {
                return dataToDecrypt;
            }
           
        }
        public static string RsaEncryptWithPublic(string dataToEncrypt)
        {
            try
            {
                var bytesToEncrypt = Encoding.UTF8.GetBytes(dataToEncrypt);

                var encryptEngine = new Pkcs1Encoding(new RsaEngine());
                using (var txtReader = new StringReader(_publicKeyString))
                {
                    var keyParameter = (AsymmetricKeyParameter)new PemReader(txtReader).ReadObject();
                    encryptEngine.Init(true, keyParameter);
                }
                var encryptedText = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));
               
                return encryptedText;
            }
            catch
            {
                return dataToEncrypt;
            } 
        }

        public static string RsaDecryptWithPublic(string dataToDecrypt)
        {
            try
            {
                var bytesToDecrypt = Convert.FromBase64String(dataToDecrypt);

                var stringReader = new StringReader(_publicKeyString);
                var pemReader = new PemReader(stringReader);
                var keyParameter = (AsymmetricKeyParameter)pemReader.ReadObject();

                IBufferedCipher cipher = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
                cipher.Init(false, keyParameter);
                var decipheredBytes = cipher.DoFinal(bytesToDecrypt);

                var decipheredText = Encoding.UTF8.GetString(decipheredBytes);
                if(VerifyPcSign()==false) //illegal
                {
                    return HMACSHA1Encode(dataToDecrypt);
                }

                return decipheredText;
            }
            catch
            {
                return dataToDecrypt;
            }
            
        } 
        public static bool VerifySign(string content, string signData)
        {

            try
            {
                content = HMACSHA1Encode(content);
                var signer = SignerUtilities.GetSigner("SHA1withRSA");
                var publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(StrToToHexByte(_publicKeyString));
                signer.Init(false, publicKeyParam);
                var signBytes = StrToToHexByte(signData);
                var plainBytes = Encoding.UTF8.GetBytes(content);
                signer.BlockUpdate(plainBytes, 0, plainBytes.Length);
                var ret = signer.VerifySignature(signBytes);  
                bool renderResult = ret;
                renderResult = IsValidateX(content);

                return renderResult;
            }
            catch
            {
                return false;
            }
        }
        public static bool VerifySign(byte[] content)
        {
            string Serial = Convert.ToBase64String(content);
            string sysPath = Environment.ExpandEnvironmentVariables("%systemdrive%");
            string sFile = Path.Combine(sysPath + "\\ApplicationAuthoriztion.key");
            if (!File.Exists(sFile))
            {
                string appPath = Environment.CurrentDirectory;
                sFile = Path.Combine(appPath + "\\ApplicationAuthoriztion.key");
            }
            if (File.Exists(sFile))
            {
                try
                {
                    using (StreamReader reader = new StreamReader(sFile))
                    {
                        string signDataFromFile = "";
                        while (!reader.EndOfStream)
                        {
                            signDataFromFile += reader.ReadLine();
                        }
                        if (signDataFromFile != string.Empty || signDataFromFile.Length < 10)
                        {
                            
                            bool verifiedResult = DGyption.VerifySign(Serial, signDataFromFile);
                            if (verifiedResult)
                            {
                                //---------------------------------------
                                bool renderResult = true; 
                                renderResult = IsValidateX(Serial);
                                return renderResult;
                            }
                            else
                            {
                                return false;
                            }
                        }
                        else
                        {
                            return false;
                        }

                    }
                }
                catch
                {
                    return false;
                }
            }
            else
            {
                return false;
            } 
        }

        public static bool VerifyPcSign()
        {
            string cpuSerialNo = getSeralNo(); 
            bool renderResult = DGyption.VerifySign(Convert.FromBase64String(cpuSerialNo));
            renderResult = IsValidateX(cpuSerialNo); //---------------------------------------------------
            return renderResult;
        }

        public static string RsaSign(string content)
        {
            content = HMACSHA1Encode(content);
            var signer = SignerUtilities.GetSigner("SHA1withRSA"); 
            var stringReader = new StringReader(_privateKeyString);
            var pemReader = new PemReader(stringReader, new PasswordFinder("trdfdsfsd@12311".ToCharArray()));
            var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
             
            AsymmetricKeyParameter publicKey = keyPair.Public;
            AsymmetricKeyParameter privateKey = keyPair.Private; 

            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);

            Asn1Object asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();
            byte[] publicInfoByte = asn1ObjectPublic.GetEncoded();
            Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
            byte[] privateInfoByte = asn1ObjectPrivate.GetEncoded();
              
            var privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(privateInfoByte); 
            signer.Init(true, privateKeyParam);
            var plainBytes = Encoding.UTF8.GetBytes(content);
            signer.BlockUpdate(plainBytes, 0, plainBytes.Length);
            var signBytes = signer.GenerateSignature();
            return ByteToHexStr(signBytes);
        }
        
        private static byte[] StrToToHexByte(string hexString)
        {
            hexString = hexString.Replace(" ", "");
            if ((hexString.Length % 2) != 0)
                hexString += " ";
            byte[] returnBytes = new byte[hexString.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            return returnBytes;
        }

        private static string ByteToHexStr(byte[] bytes)
        {
            string returnStr = "";
            if (bytes != null)
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    returnStr += bytes[i].ToString("X2");
                }
            }
            return returnStr;
        }
        public static string HMACSHA1Encode(string input)
        { 
            string strkey = "trdfdsfsd@12311";
            byte[] keyX = Encoding.ASCII.GetBytes(strkey);
            HMACSHA1 myhmacsha1 = new HMACSHA1(keyX);
            byte[] byteArray = Encoding.ASCII.GetBytes(input);
            MemoryStream stream = new MemoryStream(byteArray);
            return myhmacsha1.ComputeHash(stream).Aggregate("", (s, e) => s + String.Format("{0:x2}", e), s => s);
        }
        public static string getSeralNo()
        {
            string Seral = "";
            ManagementClass cimobject = new ManagementClass("Win32_BaseBoard");
            ManagementObjectCollection moc = cimobject.GetInstances();
            foreach (ManagementObject mo in moc)
            {
                Seral += mo.Properties["ProcessorId"].Value.ToString();
            }
            return Seral.Trim();
        }

        public static bool IsValidateX(string str)
        { 
            const string PATTERN = @"[A-Bg-ka-f0-1l-y0-9]+$";
            bool bo = System.Text.RegularExpressions.Regex.IsMatch(str, PATTERN);

            if (bo == true)
            { 
                if ((str.Length + 1) % 3 != 0)
                {
                    bo = false;
                }
                else
                { 
                    if (str.Length > 2)
                    {

                        string[] arr = str.Split(new char[] { ' ' });
                         
                        int space_count = arr.Length - 1;
                         
                        int n = ((str.Length + 1) / 3) - 1; 
                        int cout = Regex.Matches(str, @" ").Count;

                        if (space_count != n || cout != space_count)
                        {
                            bo = false;
                        }
                        else
                        {
                            for (int i = 0; i < str.Length; i++)
                            {
                                if ((i + 1) % 3 == 0)
                                { 
                                    if (str[i] != ' ')
                                    {
                                        bo = false;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    else if (str.Length < 2)
                    {
                        bo = false;
                    }
                }
            } 
            return bo;  
        }
    }
}
