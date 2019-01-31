using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using VkNet;
using VkNet.Enums.Filters;
using VkNet.Enums.SafetyEnums;
using VkNet.Model;
using VkNet.Model.RequestParams;
using VkNet.Model.RequestParams.Database;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Threading;
using WindowsInput.Native; 
using WindowsInput;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Security;

namespace VKMESTEST 
{
    class Program
    {
        private static void Auth(VkApi api, string login, string password)
        {
            Console.Write("У вас есть двухфакторная аутентификация? (Д/Н) or (Y/N) ");
            var factstate = Console.ReadLine();
            TerminOutput();
            if (factstate == "Д" || factstate == "д" || factstate == "Y" || factstate == "y")
            {
                Two_Fact_Auth(api, login, password);
            }
            else
            {
                One_Fact_Auth(api, login, password);
            }
        }

        private static void Two_Fact_Auth(VkApi api, string login, string password)
        {
            api.Authorize(new ApiAuthParams
            {
                ApplicationId = 6723320,
                Login = login,
                Password = password,
                Settings = Settings.All,
                TwoFactorAuthorization = () =>
                {
                    Console.Write("Enter Code: ");
                    return Console.ReadLine();
                }
            });
        }

        private static void One_Fact_Auth(VkApi api, string login, string password)
        {
            api.Authorize(new ApiAuthParams
            {
                ApplicationId = 6723320,
                Login = login,
                Password = password,
                Settings = Settings.All
            });
        }

        private static void Auth(VkApi api, bool prizn)
        {
            Console.Write("У вас есть двухфакторная аутентификация? (Д/Н) or (Y/N) ");
            var factstate = Console.ReadLine();
            TerminOutput();
            if (factstate == "Д" || factstate == "д" || factstate == "Y" || factstate == "y")
            {
                Two_Fact_Auth(api, prizn);
            }
            else
            {
                One_Fact_Auth(api, prizn);
            }
        }

        private static void TerminOutput()
        {
            for (int i = 0; i < 20; i++)
            {
                Console.Write('_');
            }

            Console.WriteLine();
        }

        private static void FromXmlString(RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus":
                            parameters.Modulus = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "Exponent":
                            parameters.Exponent = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "P":
                            parameters.P = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "Q":
                            parameters.Q = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "DP":
                            parameters.DP = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "DQ":
                            parameters.DQ = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "InverseQ":
                            parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                        case "D":
                            parameters.D = (string.IsNullOrEmpty(node.InnerText)
                                ? null
                                : Convert.FromBase64String(node.InnerText));
                            break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        private static string ToXmlString(RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            return string.Format(
                "<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                parameters.D != null ? Convert.ToBase64String(parameters.D) : null);
        }

        public static string RSAEncryption(string strText, string pubkey)
        {
            var publicKey = pubkey;

            var testData = Encoding.UTF8.GetBytes(strText);

            using (var rsa = new RSACryptoServiceProvider(4096))
            {
                try
                {
                    // client encrypting data with public key issued by server                    
                    FromXmlString(rsa, publicKey);

                    var encryptedData = rsa.Encrypt(testData, true);

                    var base64Encrypted = Convert.ToBase64String(encryptedData);

                    return base64Encrypted;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        public static string RSADecryption(string strText, string privkey)
        {
            var privateKey = privkey;

            var testData = Encoding.UTF8.GetBytes(strText);

            using (var rsa = new RSACryptoServiceProvider(4096))
            {
                try
                {
                    var base64Encrypted = strText;

                    // server decrypting data with private key                    
                    FromXmlString(rsa, privateKey);

                    var resultBytes = Convert.FromBase64String(base64Encrypted);
                    var decryptedBytes = rsa.Decrypt(resultBytes, true);
                    var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
                    return decryptedData.ToString();
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        private static void Two_Fact_Auth(VkApi api, bool prizn)
        {
            bool pr = false;
            while (!pr)
            {
                try
                {
                    Console.Write("Your nick:");
                    var login = Console.ReadLine();
                    TerminOutput();
                    Console.Write("Your password:");
                    var pass = Console.ReadLine();
                    TerminOutput();
                    api.Authorize(new ApiAuthParams
                    {
                        ApplicationId = 6723320,
                        Login = login,
                        Password = pass,
                        Settings = Settings.All,
                        TwoFactorAuthorization = () =>
                        {
                            Console.Write("Enter Code: ");
                            return Console.ReadLine();
                        }
                    });
                    pr = true;
                    if (prizn)
                    {
                        Save_Data(login, pass);
                    }
                }
                catch
                {
                    Console.WriteLine("Произошла ошибка авторизации, попробуйте еще раз.");
                    TerminOutput();
                }
            }
        }

        private static void One_Fact_Auth(VkApi api, bool prizn)
        {
            bool pr = false;
            while (!pr)
            {
                try
                {
                    Console.Write("Your nick:");
                    var login = Console.ReadLine();
                    TerminOutput();
                    Console.Write("Your password:");
                    var pass = Console.ReadLine();
                    TerminOutput();
                    api.Authorize(new ApiAuthParams
                    {
                        ApplicationId = 6723320,
                        Login = login,
                        Password = pass,
                        Settings = Settings.All
                    });
                    pr = true;
                    if (prizn)
                    {
                        Save_Data(login, pass);
                    }
                }
                catch
                {
                    Console.WriteLine("Произошла ошибка авторизации, попробуйте еще раз.");
                    TerminOutput();
                }
            }
        }

        private static string Encryption(string data, string key)
        {
            var encryptor = new CamelliaEngine();
            var strkey = key;
            ICipherParameters param = new KeyParameter(Convert.FromBase64String(strkey));
            encryptor.Init(true, param);
            var strlengthbytes = Encoding.UTF8.GetByteCount(data);

            if (strlengthbytes > 16 && strlengthbytes % 16 != 0)
            {
                for (int i = 0; i < 16 - strlengthbytes % 16; i++)
                {
                    data += " ";
                }

            }

            var encdata = Encoding.UTF8.GetBytes(data);

            var decmes = "";
            if (encdata.Length < 16)
            {
                for (int i = 0; i < 16 - encdata.Length; i++)
                {
                    data += " ";
                }

                encdata = Encoding.UTF8.GetBytes(data);
                byte[] decdata = new byte[encdata.Length];
                encryptor.ProcessBlock(encdata, 0, decdata, 0);
                decmes = Convert.ToBase64String(decdata);
            }


            if (encdata.Length > 16)
            {

                byte[] decdata = new byte[encdata.Length];
                for (int i = 0; i < encdata.Length; i += 16)
                {
                    encryptor.ProcessBlock(encdata, i, decdata, i);
                    if (i + 16 > encdata.Length)
                    {
                        break;
                    }
                }

                decmes = Convert.ToBase64String(decdata);
            }

            return decmes;
        }

        private static string Decryption(string curmessage, string key)
        {
            var decryptor = new CamelliaEngine();

            var strkey = key;
            ICipherParameters param = new KeyParameter(Convert.FromBase64String(strkey));
            decryptor.Init(false, param);

            var nbts = Convert.FromBase64String(curmessage);
            var ndbts = new byte[nbts.Length];
            if (ndbts.Length <= 16)
            {
                decryptor.ProcessBlock(nbts, 0, ndbts, 0);
                return Encoding.UTF8.GetString(ndbts);
            }

            for (int i = 0; i < ndbts.Length; i += 16)
            {
                decryptor.ProcessBlock(nbts, i, ndbts, i);
            }

            return Encoding.UTF8.GetString(ndbts);
        }

        private static void Send_Mes(object mesargums)
        {
            Array mesargar = new object[3];
            mesargar = (Array) mesargums;
            var send = (VkApi) mesargar.GetValue(0);
            var userid = (int) mesargar.GetValue(1);
            var SimKey = (string) mesargar.GetValue(2);
            //Console.WriteLine(SimKey);
            while (true)
            {
                var kolvosim = 0;
                var random = new Random();
                var randid = random.Next(99999);
                Console.Write("{0}: ", send.Account.GetProfileInfo().FirstName);

                var message = Console.ReadLine();
                var crmessage = Encryption(message, SimKey);
                send.Messages.Send(new MessagesSendParams
                {
                    UserId = userid,
                    RandomId = randid,
                    Message = crmessage
                });
            }
        }

        private static void Get_Mes(object mesargums)
        {
            InputSimulator sim = new InputSimulator();
            var predmessage = "zh";
            Array mesargar = new object[3];
            mesargar = (Array) mesargums;
            var get = (VkApi) mesargar.GetValue(0);
            var userid = (int) mesargar.GetValue(1);
            var SimKey = (string) mesargar.GetValue(2);
            Console.WriteLine(SimKey);
            var name = "";
            bool messtate = false;
            while (true)
            {
                var curmessage = "";
                var getDialogs = get.Messages.GetDialogs(new MessagesDialogsGetParams
                {
                    Count = 200
                });
                for (var i = 0; i < 200; i++)
                {
                    if (getDialogs.Messages[i].UserId == userid)
                    {
                        curmessage = getDialogs.Messages[i].Body;
                        messtate = (bool) getDialogs.Messages[i].Out;
                        if (messtate)
                        {
                            name = get.Account.GetProfileInfo().FirstName;
                        }
                        else
                        {
                            name = get.Users.Get(new long[] {userid}).FirstOrDefault().FirstName;
                        }

                        break;
                    }
                }

                string decmessage;
                try
                {
                    decmessage = Decryption(curmessage, SimKey);
                }
                catch
                {
                    decmessage = curmessage;
                }

                if (predmessage != decmessage && !messtate)
                {
                    Console.SetCursorPosition(0, Console.CursorTop - 1);
                    ClearCurrentConsoleLine();
                    Console.WriteLine("{0}: {1}", name, decmessage);
                    TerminOutput();
                    Console.Write("{0}: ", get.Account.GetProfileInfo().FirstName);
                    //sim.Keyboard.KeyPress(VirtualKeyCode.DOWN);
                    //sim.Keyboard.KeyPress(VirtualKeyCode.END);


                }

                predmessage = decmessage;
                Thread.Sleep(50);
            }
        }

        private static int Find_Friend_By_Name(VkApi api)
        {
            var idsob = 0;
            Console.WriteLine("Идет получние списка друзей...");
            TerminOutput();
            var friend_list = api.Friends.Get(new FriendsGetParams
            {
                Order = FriendsOrder.Hints,
                Fields = ProfileFields.FirstName,
                Count = 6000,
                NameCase = NameCase.Nom
            });
            Console.WriteLine("Список друзей получен");
            TerminOutput();
            Console.Write("Введите имя вашего друга (точно как в ВК):");
            var namesob = Console.ReadLine();
            TerminOutput();

            for (var i = 0; i < 6000; i++)
            {
                if (friend_list[i].FirstName != namesob) continue;
                var surname = friend_list[i].LastName;
                Console.Write("Его фамилия - {0}? (Д/Н) or (Y/N) ", surname);
                var status = Console.ReadLine();
                TerminOutput();
                if (status == "Н" || status == "н" || status == "N" || status == "n") continue;
                idsob = (int) friend_list[i].Id;
                break;
            }

            return idsob;
        }

        private static int Get_CountryId_By_Name(VkApi api, string namecountry)
        {
            int countryid = 0;
            var countries_list = api.Database.GetCountries(true, count: 1000);
            for (int i = 0; i < 1000; i++)
            {
                if (countries_list[i].Title == namecountry)
                {
                    countryid = (int) countries_list[i].Id;
                    break;
                }
            }

            return countryid;
        }

        private static int Get_CityId_By_Name(VkApi api, string namecity, int countryid)
        {
            int cityid = 0;
            var cities_list = api.Database.GetCities(new GetCitiesParams
            {
                CountryId = countryid,
                NeedAll = true,
                Query = namecity

            });
            for (var i = 0; i < 1000; i++)
            {
                Console.Write("{0}? (Д/Н) ", cities_list[i].Region);
                var stat = Console.ReadLine();
                TerminOutput();
                if (stat == "Д" || stat == "д" || stat == "Y" || stat == "y")
                {
                    cityid = (int) cities_list[i].Id;
                    break;
                }
            }

            return cityid;
        }

        private static int Other_Search(VkApi api)
        {
            int idsob;
//            try
//            {
//                idsob = Hand_Search(api);
//            }
//            catch
//            {
            Console.WriteLine("Извините, программа не смогла найти пользовтеля по введенным данным(((");
            TerminOutput();
            Console.Write("Введите id собеседника: ");
            idsob = Convert.ToInt32(Console.ReadLine());
            TerminOutput();
            //}
            return idsob;
        }

        private static int Hand_Search(VkApi api)
        {
            Console.WriteLine(
                "Если какие то из параметров отсутствуют у пользователя, то просто пропустите их ввод, нажав клавишу Enter.");
            TerminOutput();
            Console.Write("Введите имя собеседника: ");
            var namesob = Console.ReadLine();
            TerminOutput();
            Console.Write("Введите фамилию собеседника: ");
            var sunamesob = Console.ReadLine();
            TerminOutput();
            Console.Write("Введите название страны: ");
            var namecountry = Console.ReadLine();
            TerminOutput();
            Console.Write("Введите название города: ");
            var namecity = Console.ReadLine();
            TerminOutput();
            var countryid = Get_CountryId_By_Name(api, namecountry);
            var cityid = Get_CityId_By_Name(api, namecity, countryid);
            Console.Write("Введите возраст от: ");
            var age_from = Console.ReadLine();
            TerminOutput();
            Console.Write("Введите возраст до: ");
            var age_to = Console.ReadLine();
            TerminOutput();
            var users = api.Users.Search(new UserSearchParams
            {
                AgeFrom = Convert.ToUInt16(age_from),
                AgeTo = Convert.ToUInt16(age_to),
                Query = namesob + " " + sunamesob,
                City = cityid,
                Country = countryid,
                Count = 100
            });
            return (int) users[1].Id;

        }

        private static bool Check_Key(VkApi api, int idsob)
        {
            bool pr = true;
            Console.WriteLine("Идет проверка на присутствие ключа в чате...");
            TerminOutput();
            var getDialogs = api.Messages.GetDialogs(new MessagesDialogsGetParams
            {
                Count = 200
            });
            var curmessage = "";
            var state = false;
            for (var i = 0; i < 200; i++)
            {
                if (getDialogs.Messages[i].UserId == idsob)
                {
                    state = (bool) getDialogs.Messages[i].Out;
                    curmessage = getDialogs.Messages[i].Body;
                    break;
                }
            }

            if (curmessage.Length < 13)
            {
                pr = false;
                Console.WriteLine("Собеседник не отправил Вам свой ключ((");
                TerminOutput();
                Console.WriteLine("Опять вся надежда на Вас!!!");
                TerminOutput();
                return false;
            }

            if (curmessage.Substring(0, 13) == "<RSAKeyValue>" && state == false)
            {
                Console.WriteLine("Ключ есть!");
                TerminOutput();
                return true;
            }

            if (pr)
            {
                Console.WriteLine("Собеседник не отправил Вам свой ключ((");
                TerminOutput();
                Console.WriteLine("Опять вся надежда на Вас!!!");
                TerminOutput();
                return false;
            }

            return false;
        }

        private static void Send_Key(VkApi api, string pubkey, int idsob, bool pr)
        {
            Console.WriteLine("Идет отправка публичного ключа...");
            var random = new Random();
            var randid = random.Next(99999);
            api.Messages.Send(new MessagesSendParams
            {
                UserId = idsob,
                RandomId = randid,
                Message = pubkey
            });
            TerminOutput();
            Console.WriteLine("Ключ успешно отправлен!!!");
            TerminOutput();
            if (pr)
            {
                Console.WriteLine("Дожидаемся получения ключа...");
                TerminOutput();
                Console.WriteLine("Можете сходить за кофе");
            }
        }

        private static string Get_Key(VkApi api, int idsob)
        {
            string newkey;
            while (true)
            {
                var getDialogs = api.Messages.GetDialogs(new MessagesDialogsGetParams
                {
                    Count = 200
                });
                Thread.Sleep(500);
                var curmessage = "";
                var state = false;
                int i;
                for (i = 0; i < 200; i++)
                {
                    if (getDialogs.Messages[i].UserId == idsob)
                    {
                        state = (bool) getDialogs.Messages[i].Out;
                        curmessage = getDialogs.Messages[i].Body;
                        //Console.WriteLine(state);
                        break;
                    }
                }

                //Console.WriteLine("Ожидается ключ");
                //Console.WriteLine(curmessage);
                if (curmessage.Length < 13)
                {
                    continue;
                }

                if (curmessage.Substring(0, 13) == "<RSAKeyValue>" && state == false)
                {
                    newkey = curmessage;
                    break;
                }
            }

            TerminOutput();
            Console.WriteLine("Ключ получен!!!");
            TerminOutput();
            return newkey;
        }

        private static string ChangeKeys(VkApi api, string pubkey, int idsob, ref bool me_or_him)
        {
            string newpubkey;
            if (Check_Key(api, idsob) == false)
            {
                Send_Key(api, pubkey, idsob, true);
                newpubkey = Get_Key(api, idsob);
                me_or_him = true;
            }
            else
            {
                me_or_him = false;
                newpubkey = Get_Key(api, idsob);
                Send_Key(api, pubkey, idsob, false);
            }

            return newpubkey;
        }

        private static string Generate_Sim_Key()
        {
            var keygen = new CipherKeyGenerator();
            keygen.Init(new KeyGenerationParameters(new SecureRandom(), 256));
            var key = Convert.ToBase64String(keygen.GenerateKey());
            return key;
        }

        private static void Send_Sim_Key(VkApi api, int idsob, string SimKey, string pubkey)
        {
            Console.WriteLine("Идет отправка симметричного ключа...");
            var random = new Random();
            var randid = random.Next(99999);
            var CryptedSimKey = RSAEncryption(SimKey, pubkey);
            api.Messages.Send(new MessagesSendParams
            {
                UserId = idsob,
                RandomId = randid,
                Message = CryptedSimKey
            });
            TerminOutput();
            Console.WriteLine("Ключ успешно отправлен!!!");
            TerminOutput();
        }

        private static string Get_Sim_Key(VkApi api, int idsob, string privkey)
        {
            Console.WriteLine("Получаем ключ симметричного шифрования...");
            TerminOutput();
            string newkey;
            while (true)
            {
                var getDialogs = api.Messages.GetDialogs(new MessagesDialogsGetParams
                {
                    Count = 200
                });
                Thread.Sleep(500);
                var curmessage = "";
                var state = false;
                int i;
                for (i = 0; i < 200; i++)
                {
                    if (getDialogs.Messages[i].UserId == idsob)
                    {
                        state = (bool) getDialogs.Messages[i].Out;
                        curmessage = getDialogs.Messages[i].Body;
                        break;
                    }
                }

                if (state == false)
                {
                    newkey = RSADecryption(curmessage, privkey);
                    break;
                }
            }

            Console.WriteLine("Ключ получен!!!");
            TerminOutput();
            Console.WriteLine(newkey);
            return newkey;
        }

        private static void Save_Data(string login, string password)
        {
            string docPath = Environment.CurrentDirectory;
            using (StreamWriter outputFile = new StreamWriter(Path.Combine(docPath, "LoginData.txt"), true))
            {
                outputFile.WriteLine(login);
                outputFile.WriteLine(password);
            }
        }

        public static void ClearCurrentConsoleLine()
        {
            int currentLineCursor = Console.CursorTop;
            Console.SetCursorPosition(0, Console.CursorTop);
            Console.Write(new string(' ', Console.WindowWidth));
            Console.SetCursorPosition(0, currentLineCursor);
        }

        private static void Auth_With_Saved_Data(VkApi api)
        {
            Console.WriteLine("Попытка найти сохраненные данные авторизации...");
            TerminOutput();
            string docPath = Environment.CurrentDirectory;
            string[] lines = File.ReadAllLines(Path.Combine(docPath, "LoginData.txt"));
            var login = lines[0];
            var password = lines[1];
            Console.WriteLine("Данные для авторизации найдены.");
            TerminOutput();
            Auth(api, login, password);
        }

        private static void Auth_Without_Saved_Data(VkApi api)
        {
            bool prizn;
            Console.WriteLine("Не удалось найти данные для входа.");
            TerminOutput();
            Console.Write("Хотите сохранить логин и пароль, чтобы не вводить их при каждой авторизации? (Д/Н) or (Y/N) ");
            var strprizn = Console.ReadLine();
            TerminOutput();
            if (strprizn == "Д" || strprizn == "д" || strprizn == "Y" || strprizn == "y")
            {
                prizn = true;
            }
            else
            {
                prizn = false;
            }
            Auth(api, prizn);
        }
    

    private static void Main(string[] args)
        {   
            Console.OutputEncoding = Encoding.UTF8;
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(4096);
            var pubkey = ToXmlString(RSA, false);
            
            bool prizn;
            var api = new VkApi();
            
            try
            {    
                Auth_With_Saved_Data(api);
            }
            catch
            {
                Auth_Without_Saved_Data(api);
            }
           
            api.Account.SetOffline();
            
            var myname = api.Account.GetProfileInfo().FirstName;
            Console.WriteLine("Доброго времени суток, {0}", myname);
            TerminOutput();
            Console.WriteLine("Ваш ID: {0}",api.UserId);
            TerminOutput();
            
            int idsob = 0;
            Console.Write("Беседа будет с другом? (Д/Н) or (Y/N) ");
            var stat = Console.ReadLine();
            TerminOutput();

            if (stat == "Д" || stat == "д" || stat == "Y" || stat == "y")
            {
                try
                {
                    idsob = Find_Friend_By_Name(api);
                }
                catch
                {
                    Console.WriteLine("Извините, программа не смогла автоматически найти собеседника((");
                    TerminOutput();
                    Console.WriteLine("Попробуйте найти собеседника вручную.");
                    TerminOutput();
                    Thread.Sleep(500);
                    idsob = Other_Search(api);
                }
            }
            
            if (stat == "н" || stat == "Н" || stat == "N" || stat == "n")
            {
                Console.Write("Тогда введите ID собеседника:");
                idsob = Convert.ToInt32(Console.ReadLine());
                TerminOutput();
            }
            
            TerminOutput();

            var privkey = ToXmlString(RSA, true);
            Console.WriteLine("Запускается беседа...");
            TerminOutput();
            
            bool me_or_him = true;
            var newpubkey = ChangeKeys(api, pubkey, idsob, ref me_or_him);
            Console.WriteLine(me_or_him);
            pubkey = newpubkey;
            
            string SimKey;
            if (me_or_him)
            {
                SimKey = Generate_Sim_Key();
                Send_Sim_Key(api, idsob, SimKey, pubkey);
            }
            else
            {
                SimKey = Get_Sim_Key(api, idsob, privkey);
            }
            
            
            object mesargums = new object[] {api, idsob, SimKey};
            
            var SendMesThread = new Thread(Send_Mes);
            var GetMesThread = new Thread(Get_Mes);
            
            SendMesThread.Start(mesargums);
            GetMesThread.Start(mesargums);
            
            TerminOutput();
            
        }
    }
}
